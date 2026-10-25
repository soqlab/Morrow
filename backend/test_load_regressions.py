"""Regressions found by the sustained-traffic load test (docs/LOAD_TEST_REPORT.md).

Each test here pins one behaviour that a load test caught and a functional test cannot: the
functional suite runs one request at a time against a near-empty database, so a query that is
quadratic in tenant size, a connection pool with no queue, and an error path that reports "no
findings" instead of "busy" all pass it.

The Postgres-only cases are skipped unless MORROW_TEST_PG_DSN names a disposable server, following
test_postgres_integration.py. The rest run on SQLite and always execute.
"""

import re
import os
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
import uuid
from datetime import datetime, timedelta, timezone

import pytest

BACKEND = os.path.dirname(os.path.abspath(__file__))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

PG_DSN = os.getenv("MORROW_TEST_PG_DSN", "").strip()
UTC = timezone.utc


# ── 1. The pool waits instead of failing ─────────────────────────────────────

class FakePool:
    """A pool that is exhausted until `release()` is called, like psycopg2's under load."""

    def __init__(self):
        from psycopg2.pool import PoolError

        self._error = PoolError
        self.available = False
        self.calls = 0

    def getconn(self):
        self.calls += 1
        if not self.available:
            raise self._error("connection pool exhausted")
        return "connection"

    def release(self):
        self.available = True


class TestPoolAcquireWaits(unittest.TestCase):
    """db_postgres._getconn_waiting must queue on a full pool, not turn the request into a 500.

    psycopg2's ThreadedConnectionPool.getconn() raises the instant maxconn connections are
    checked out. Before this, 50 concurrent readers produced 500s on /assets, /scans and
    /fix-next while Postgres itself was idle.
    """

    def test_waits_for_a_connection_to_come_back(self):
        import db_postgres

        pool = FakePool()
        threading.Timer(0.3, pool.release).start()
        started = time.monotonic()
        conn = db_postgres._getconn_waiting(pool, timeout=10.0)
        waited = time.monotonic() - started
        self.assertEqual(conn, "connection")
        self.assertGreaterEqual(waited, 0.25)
        self.assertGreater(pool.calls, 1, "should have retried rather than given up on the first PoolError")

    def test_gives_up_after_the_timeout_so_a_caller_is_never_blocked_forever(self):
        import db_postgres
        from psycopg2.pool import PoolError

        pool = FakePool()
        started = time.monotonic()
        with self.assertRaises(PoolError):
            db_postgres._getconn_waiting(pool, timeout=0.4)
        self.assertLess(time.monotonic() - started, 5.0)

    def test_a_closed_pool_fails_immediately(self):
        import db_postgres
        from psycopg2.pool import PoolError

        class ClosedPool:
            def getconn(self):
                raise PoolError("connection pool is closed")

        started = time.monotonic()
        with self.assertRaises(PoolError):
            db_postgres._getconn_waiting(ClosedPool(), timeout=30.0)
        self.assertLess(time.monotonic() - started, 1.0, "a closed pool is not a queue")


# ── 2. Congestion is not reported as "no findings" ───────────────────────────

class TestReportingSurfacesCongestion(unittest.TestCase):
    """_latest_asset_scan_facts must not answer a saturated pool with an empty, zero-risk posture.

    It wraps its read in `except Exception` so a partly migrated deployment tolerates a missing
    table. That also swallowed PoolError, so /executive-dashboard, /board-risk and /heatmap
    answered 200 with zero assets and zero risk whenever the database was merely busy.
    """

    def test_pool_error_propagates(self):
        import app
        from psycopg2.pool import PoolError

        original = app.latest_scan_facts_for_org

        def boom(*_a, **_kw):
            raise PoolError("connection pool exhausted")

        app.latest_scan_facts_for_org = boom
        try:
            with self.assertRaises(PoolError):
                app._latest_asset_scan_facts("00000000-0000-0000-0000-000000000001")
        finally:
            app.latest_scan_facts_for_org = original

    def test_operational_error_propagates(self):
        import app
        import psycopg2

        original = app.latest_scan_facts_for_org

        def boom(*_a, **_kw):
            raise psycopg2.OperationalError("server closed the connection unexpectedly")

        app.latest_scan_facts_for_org = boom
        try:
            with self.assertRaises(psycopg2.OperationalError):
                app._latest_asset_scan_facts("00000000-0000-0000-0000-000000000001")
        finally:
            app.latest_scan_facts_for_org = original

    def test_a_missing_table_is_still_tolerated(self):
        """The original tolerance is deliberate and must survive: a half-migrated deployment
        should still render a dashboard rather than 500."""
        import app

        original = app.latest_scan_facts_for_org

        def boom(*_a, **_kw):
            raise sqlite3.OperationalError("no such table: scan_results")

        app.latest_scan_facts_for_org = boom
        try:
            self.assertEqual(app._latest_asset_scan_facts("00000000-0000-0000-0000-000000000001"), [])
        finally:
            app.latest_scan_facts_for_org = original


# ── 3. The schema carries the composite indexes the hot reads need ───────────

class TestHotPathIndexes(unittest.TestCase):
    """Every one of these serves a query that runs on a customer-facing read path.

    Without them Postgres sorts the whole tenant's rows on each request, so the cost grows with
    tenant size -- invisible on the near-empty database the functional suite uses.
    """

    def test_core_schema_declares_them(self):
        import db_postgres

        ddl = " ".join(db_postgres.POSTGRES_CORE_SCHEMA_SQL)
        for index, table, columns in (
            ("idx_audit_logs_org_id_desc", "audit_logs", "organization_id, id DESC"),
            ("idx_scan_results_org_scanned", "scan_results", "organization_id, scanned_at DESC"),
            ("idx_scan_results_org_asset_scanned", "scan_results",
             "organization_id, asset_key, scanned_at DESC"),
            ("idx_scans_org_created", "scans", "organization_id, created_at DESC"),
        ):
            self.assertIn(index, ddl, f"{index} on {table}({columns}) is missing from the core schema")

    def test_list_scan_rows_does_not_fetch_the_result_blobs_it_discards(self):
        import inspect

        import db_postgres

        src = inspect.getsource(db_postgres.pg_list_scan_rows)
        select = src[src.index("SELECT"):src.index("FROM scans")]
        self.assertNotIn("results_json", select,
                         "pg_list_scan_rows pops 'results' from every row, so selecting the blob "
                         "transfers and parses data that is never emitted")


# ── 4. Batched latest-scan lookup (the /hndl/dashboard N+1) ──────────────────

def _sqlite_fixture(path):
    conn = sqlite3.connect(path)
    conn.execute(
        """CREATE TABLE scan_results (
               id INTEGER PRIMARY KEY AUTOINCREMENT, organization_id TEXT, asset_key TEXT,
               scan_id TEXT, scanned_at TEXT, risk_level TEXT, quantum_score REAL,
               findings_count INTEGER, pq_relevance TEXT, tls_version TEXT,
               key_type TEXT, sig_algorithm TEXT)"""
    )
    conn.execute("CREATE TABLE scans (id TEXT PRIMARY KEY, organization_id TEXT, status TEXT, created_at TEXT)")
    rows = []
    for n in range(3):
        for day, risk in ((1, "low"), (2, "high"), (3, "critical")):
            rows.append(("org-a", "host%d:443" % n, "scan-%d" % day,
                         "2026-09-0%dT00:00:00Z" % day, risk, 10.0 * day, day,
                         "vulnerable", "TLSv1.2", "RSA-2048", "sha256WithRSAEncryption"))
    rows.append(("org-b", "host0:443", "scan-9", "2026-09-09T00:00:00Z", "low", 1.0, 0,
                 "pq-ready", "TLSv1.3", "Ed25519", "ed25519"))
    conn.executemany(
        "INSERT INTO scan_results (organization_id, asset_key, scan_id, scanned_at, risk_level,"
        " quantum_score, findings_count, pq_relevance, tls_version, key_type, sig_algorithm)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)
    conn.executemany("INSERT INTO scans (id, organization_id, status, created_at) VALUES (?,?,?,?)",
                     [("s%d" % i, "org-a", "completed", "2026-09-0%dT00:00:00Z" % (i + 1)) for i in range(4)]
                     + [("s9", "org-b", "completed", "2026-09-09T00:00:00Z")])
    conn.commit()
    conn.close()


class TestBatchedLatestScanResults(unittest.TestCase):
    """One query for a whole inventory, not one per asset.

    /hndl/dashboard and /hndl/timeline called latest_scan_result_for_asset() once per asset. At
    1000 assets that is 1000 sequential round trips, each borrowing a pooled connection, and the
    endpoint took over a minute while Postgres sat idle between them.
    """

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        _sqlite_fixture(self.tmp.name)
        os.environ["MORROW_SCANNER_DB"] = self.tmp.name
        os.environ.pop("MORROW_MAIN_DB_BACKEND", None)
        import importlib

        import db as db_module
        self.db = importlib.reload(db_module)
        self.token = self.db.set_current_organization_id("org-a")

    def tearDown(self):
        self.db.reset_current_organization_id(self.token)
        os.environ.pop("MORROW_SCANNER_DB", None)
        try:
            os.unlink(self.tmp.name)
        except OSError:
            pass

    def test_returns_the_newest_row_for_every_asset(self):
        keys = ["host0:443", "host1:443", "host2:443"]
        batch = self.db.latest_scan_results_for_assets(keys)
        self.assertEqual(sorted(batch), sorted(keys))
        for key in keys:
            self.assertEqual(batch[key]["scanned_at"], "2026-09-03T00:00:00Z")
            self.assertEqual(batch[key]["risk_level"], "critical")

    def test_matches_the_per_asset_lookup_it_replaces(self):
        for key in ("host0:443", "host1:443", "host2:443"):
            one = self.db.latest_scan_result_for_asset(key)
            many = self.db.latest_scan_results_for_assets([key])[key]
            self.assertEqual(one["scanned_at"], many["scanned_at"])
            self.assertEqual(one["risk_level"], many["risk_level"])
            self.assertEqual(one["scan_id"], many["scan_id"])

    def test_stays_inside_the_tenant(self):
        batch = self.db.latest_scan_results_for_assets(["host0:443"])
        self.assertEqual(batch["host0:443"]["risk_level"], "critical")  # org-a's row, not org-b's

    def test_unknown_and_empty_keys_are_harmless(self):
        self.assertEqual(self.db.latest_scan_results_for_assets([]), {})
        self.assertEqual(self.db.latest_scan_results_for_assets(["", "  "]), {})
        self.assertEqual(self.db.latest_scan_results_for_assets(["nope:443"]), {})

    def test_count_scans_agrees_with_listing_them(self):
        self.assertEqual(self.db.count_scans(), len(self.db.list_scan_rows(limit=10000)))
        other = self.db.set_current_organization_id("org-b")
        try:
            self.assertEqual(self.db.count_scans(), 1)
        finally:
            self.db.reset_current_organization_id(other)


# ── 5. The same batching, against a real Postgres ────────────────────────────

@pytest.mark.skipif(not PG_DSN, reason="set MORROW_TEST_PG_DSN to run against a real Postgres")
class TestBatchedLatestScanResultsPostgres(unittest.TestCase):
    """DISTINCT ON has to pick the same row the per-asset ORDER BY ... LIMIT 1 picks."""

    @classmethod
    def setUpClass(cls):
        import psycopg2

        cls.dbname = "pq_loadreg_%s" % uuid.uuid4().hex[:8]
        admin = psycopg2.connect(PG_DSN)
        admin.autocommit = True
        with admin.cursor() as cur:
            cur.execute("CREATE DATABASE %s" % cls.dbname)
        admin.close()
        base = PG_DSN.rsplit("/", 1)[0]
        cls.dsn = "%s/%s" % (base, cls.dbname)
        os.environ["MORROW_PRODUCT_DATABASE_URL"] = cls.dsn
        os.environ["MORROW_MAIN_DB_BACKEND"] = "postgres"

        import db_postgres
        db_postgres.close_pools()
        db_postgres.ensure_postgres_core_schema(cls.dsn)
        cls.db_postgres = db_postgres

        now = datetime.now(UTC)
        with db_postgres.pg_product_conn(cls.dsn) as conn:
            with conn.cursor() as cur:
                for n in range(3):
                    for day in (1, 2, 3):
                        cur.execute(
                            "INSERT INTO scan_results (organization_id, asset_key, scan_id,"
                            " scanned_at, risk_level, quantum_score, findings_count) "
                            "VALUES (%s,%s,%s,%s,%s,%s,%s)",
                            ("org-a", "host%d:443" % n, "scan-%d" % day,
                             now - timedelta(days=4 - day), "critical" if day == 3 else "low",
                             float(day), day))
                cur.execute(
                    "INSERT INTO scan_results (organization_id, asset_key, scan_id, scanned_at,"
                    " risk_level, quantum_score, findings_count) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                    ("org-b", "host0:443", "scan-9", now, "low", 0.0, 0))

    @classmethod
    def tearDownClass(cls):
        import psycopg2

        cls.db_postgres.close_pools()
        os.environ.pop("MORROW_PRODUCT_DATABASE_URL", None)
        os.environ.pop("MORROW_MAIN_DB_BACKEND", None)
        admin = psycopg2.connect(PG_DSN)
        admin.autocommit = True
        with admin.cursor() as cur:
            cur.execute("DROP DATABASE IF EXISTS %s WITH (FORCE)" % cls.dbname)
        admin.close()

    def test_batch_matches_the_per_asset_query(self):
        keys = ["host0:443", "host1:443", "host2:443"]
        batch = self.db_postgres.pg_latest_scan_results_for_assets("org-a", keys, dsn=self.dsn)
        self.assertEqual(sorted(batch), sorted(keys))
        for key in keys:
            one = self.db_postgres.pg_latest_scan_result_for_asset("org-a", key, dsn=self.dsn)
            self.assertEqual(one["scan_id"], batch[key]["scan_id"])
            self.assertEqual(one["scanned_at"], batch[key]["scanned_at"])
            self.assertEqual(batch[key]["risk_level"], "critical")

    def test_does_not_cross_tenants(self):
        batch = self.db_postgres.pg_latest_scan_results_for_assets("org-b", ["host0:443"], dsn=self.dsn)
        self.assertEqual(batch["host0:443"]["scan_id"], "scan-9")

    def test_count_scans_is_a_count(self):
        self.assertEqual(self.db_postgres.pg_count_scans("org-a", dsn=self.dsn), 0)

    def test_the_new_indexes_exist_after_bootstrap(self):
        with self.db_postgres.pg_product_conn(self.dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT indexname FROM pg_indexes WHERE schemaname='public'")
                names = {row[0] for row in cur.fetchall()}
        for index in ("idx_audit_logs_org_id_desc", "idx_scan_results_org_scanned",
                      "idx_scan_results_org_asset_scanned", "idx_scans_org_created"):
            self.assertIn(index, names)


# ── 6. The reporting read is one query per database ──────────────────────────


def _full_sqlite_db(path, orgs=("org-a", "org-b"), assets=5, scans_per_asset=6):
    """A real database with the production schema and several scans per asset."""
    os.environ["MORROW_SCANNER_DB"] = path
    os.environ.pop("MORROW_MAIN_DB_BACKEND", None)
    import importlib

    import db as db_module
    db = importlib.reload(db_module)
    db.init_db()
    for org in orgs:
        token = db.set_current_organization_id(org)
        try:
            for n in range(assets):
                for s in range(scans_per_asset):
                    db.save_scan_asset_summaries(
                        "scan-%s-%d-%d" % (org, n, s),
                        "2026-09-%02dT00:00:00Z" % (s + 1),
                        [{"host": "h%d.%s" % (n, org), "port": 443,
                          "risk": "critical" if s else "low",
                          "quantum_risk_score": float(s), "findings": [],
                          "tls_version": "TLSv1.3", "key_type": "RSA",
                          "sig_algorithm": "sha256WithRSAEncryption"}])
        finally:
            db.reset_current_organization_id(token)
    return db


class TestLatestScanFactsIsOneQuery(unittest.TestCase):
    """The reporting read returns one row per asset from the database, not the whole history.

    _latest_asset_scan_facts() used to ask for every scan result the tenant had ever recorded
    (list_scan_results_since("1970-01-01", limit=50000)), de-duplicate to the newest row per asset
    in Python and sort them there, with the caller's own limit applied only afterwards. That made
    the cost and the peak memory of /executive-dashboard, /board-risk, /heatmap, /cbom and
    /crypto-agility a function of the tenant's scan history rather than of its inventory.
    """

    ASSETS = 5
    SCANS = 6

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.previous = os.environ.get("MORROW_SCANNER_DB")
        self.db = _full_sqlite_db(self.tmp.name, assets=self.ASSETS, scans_per_asset=self.SCANS)
        self.token = self.db.set_current_organization_id("org-a")

    def tearDown(self):
        self.db.reset_current_organization_id(self.token)
        if self.previous is None:
            os.environ.pop("MORROW_SCANNER_DB", None)
        else:
            os.environ["MORROW_SCANNER_DB"] = self.previous
        try:
            os.unlink(self.tmp.name)
        except OSError:
            pass

    def test_returns_one_row_per_asset_not_one_per_scan(self):
        history = self.db.list_scan_results_since("1970-01-01T00:00:00Z", limit=50000)
        facts = self.db.latest_scan_facts_for_org(limit=5000)
        self.assertEqual(len(history), self.ASSETS * self.SCANS)
        self.assertEqual(len(facts), self.ASSETS,
                         "the database must de-duplicate to one row per asset, not Python")

    def test_the_row_it_keeps_is_the_one_the_old_python_pass_kept(self):
        """Equivalence, on a database with duplicate scans per asset."""
        history = self.db.list_scan_results_since("1970-01-01T00:00:00Z", limit=50000)
        expected = {}
        for row in history:  # oldest first; the last write per key wins, as the old code did
            expected[row["asset_key"]] = row
        got = {row["asset_key"]: row for row in self.db.latest_scan_facts_for_org(limit=5000)}
        self.assertEqual(sorted(got), sorted(expected))
        for key, row in expected.items():
            for column in ("scan_id", "scanned_at", "risk_level", "quantum_score", "key_type",
                           "sig_algorithm", "tls_version", "findings_count"):
                self.assertEqual(got[key][column], row[column], "%s.%s" % (key, column))

    def test_newest_first_and_the_limit_is_applied_by_the_database(self):
        facts = self.db.latest_scan_facts_for_org(limit=2)
        self.assertEqual(len(facts), 2)
        stamps = [row["scanned_at"] for row in facts]
        self.assertEqual(stamps, sorted(stamps, reverse=True))

    def test_it_is_a_single_statement(self):
        """One SELECT for the whole inventory, whatever the history holds."""
        statements = []
        conn = self.db.get_connection()
        conn.set_trace_callback(statements.append)
        original = self.db.get_connection
        self.db.get_connection = lambda *a, **k: conn
        try:
            self.db.latest_scan_facts_for_org(limit=5000)
        finally:
            self.db.get_connection = original
            # The code under test now closes the connection it is handed, so by the time
            # this runs the handle may already be closed and clearing the trace callback
            # raises ProgrammingError("Cannot operate on a closed database"). That failed
            # the test in its teardown, after the assertion it exists for had already
            # passed. Closed is the outcome we want anyway -- a closed connection has no
            # callback left to leak.
            try:
                conn.set_trace_callback(None)
            except sqlite3.ProgrammingError:
                pass
        selects = [x for x in statements if x.strip().upper().startswith("SELECT")]
        self.assertEqual(len(selects), 1, "expected one SELECT, got: %r" % (selects,))

    def test_it_stays_inside_the_tenant(self):
        other = self.db.set_current_organization_id("org-b")
        try:
            facts = self.db.latest_scan_facts_for_org(limit=5000)
        finally:
            self.db.reset_current_organization_id(other)
        self.assertTrue(all(".org-b" in row["asset_key"] for row in facts), facts)


# ── 7. Reports read the database the deployment actually uses ────────────────


class TestReportsNameTheDatabaseTheyRead(unittest.TestCase):
    """/crypto-agility, /migration-velocity, /search and the quantum timeline read core tables
    through the dialect router, and say when a figure could not be measured.

    They used to run SQLite-only statements through app._db() inside `except Exception: pass`, so
    on a Postgres deployment the remediation list, the scan cadence, the asset inventory and the
    readiness percentage were all silently zero and the endpoint still answered 200.
    """

    def test_no_core_table_read_is_swallowed(self):
        import inspect

        import app

        for handler in (app.api_crypto_agility, app.api_migration_velocity, app.api_search,
                        app.api_qday_countdown, app.api_evidence_build):
            src = inspect.getsource(handler)
            for table in ("FROM scan_results", "FROM remediations", "FROM assets", "FROM scans"):
                self.assertNotIn(
                    table, src,
                    "%s still reads %s from the local SQLite file; on a Postgres deployment that "
                    "table is empty there" % (handler.__name__, table))

    def test_a_failed_read_is_reported_not_zeroed(self):
        import app

        def boom():
            raise RuntimeError("boom")

        collected = []
        self.assertEqual(app._aux(collected, "remediations", boom, []), [])
        self.assertEqual(collected,
                         [{"metric": "remediations", "reason": "Query failed: RuntimeError"}])

    def test_congestion_still_propagates(self):
        import psycopg2

        import app

        for error in (app._pg_pool.PoolError("full"), psycopg2.OperationalError("gone")):
            def raiser(exc=error):
                raise exc

            with self.assertRaises(type(error)):
                app._aux([], "remediations", raiser, [])

    def test_a_missing_service_table_counts_zero_but_a_broken_query_is_reported(self):
        import app

        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        try:
            conn = sqlite3.connect(tmp.name)
            collected = []
            self.assertEqual(
                app._aux_sqlite_scalar(conn, collected, "playbooks",
                                       "SELECT COUNT(*) FROM playbooks WHERE org_id=?", ("o",), 0), 0)
            self.assertEqual(collected, [], "a table the deployment never created is not a failure")
            conn.execute("CREATE TABLE playbooks (org_id TEXT)")
            self.assertEqual(
                app._aux_sqlite_scalar(conn, collected, "playbooks",
                                       "SELECT COUNT(*) FROM playbooks WHERE org_id=? AND nope=?",
                                       ("o", "x"), 0), 0)
            self.assertEqual([c["metric"] for c in collected], ["playbooks"])
            conn.close()
        finally:
            os.unlink(tmp.name)


# ── 8. POST /v1/remediation-candidates: the HNDL N+1, on a write path ────────


class TestRemediationCandidatesBatching(unittest.TestCase):
    """The candidate builder lists the scans once, not once per asset."""

    def test_the_lookup_loads_each_scan_at_most_once(self):
        import app
        import db as db_module

        calls = {"list": 0, "load": 0, "per_asset": 0, "batch": 0}
        rows = [{"id": "s1", "created_at": "2026-09-01T00:00:00Z"}]
        scan = {"results": [{"asset_key": "known:443", "key_type": "RSA"}]}

        def list_scan_rows(limit=20):
            calls["list"] += 1
            return rows

        def load_scan_row(scan_id):
            calls["load"] += 1
            return scan

        def per_asset(key):
            calls["per_asset"] += 1
            return {}

        def batched(keys):
            calls["batch"] += 1
            return {}

        original = (app.list_scan_rows, app.load_scan_row, app.latest_scan_result_for_asset,
                    db_module.latest_scan_results_for_assets)
        app.list_scan_rows, app.load_scan_row = list_scan_rows, load_scan_row
        app.latest_scan_result_for_asset = per_asset
        db_module.latest_scan_results_for_assets = batched
        try:
            keys = ["known:443"] + ["miss%d:443" % n for n in range(25)]
            lookup = app._latest_full_scan_result_lookup(fallback_keys=keys)
            for key in keys:
                lookup(key)
        finally:
            (app.list_scan_rows, app.load_scan_row, app.latest_scan_result_for_asset,
             db_module.latest_scan_results_for_assets) = original
        self.assertEqual(calls["list"], 1, "the scan list must be read once for the whole inventory")
        self.assertEqual(calls["load"], 1, "each scan must be loaded at most once")
        self.assertEqual(calls["per_asset"], 0, "the fallback must not be one query per asset")
        self.assertEqual(calls["batch"], 1, "the fallback is one batched query for every asset")

    def test_the_endpoints_use_the_batched_lookup(self):
        import inspect

        import app

        for handler in (app.api_v1_remediation_candidates, app.api_v1_policy_evaluate):
            src = inspect.getsource(handler)
            self.assertIn("_latest_full_scan_result_lookup", src, handler.__name__)
            self.assertIn("latest_for(ak)", src, handler.__name__)


# ── 9. The operator overview is served from a precomputed snapshot ───────────


class _SnapshotFixture:
    """A throwaway SQLite feature store with the journal and snapshot tables."""

    def __enter__(self):
        self.tmp = tempfile.mkdtemp(prefix="pq-snap-")
        self.previous = {k: os.environ.get(k) for k in
                         ("MORROW_SCANNER_DB", "MORROW_MAIN_DB_BACKEND", "MORROW_FEATURE_STORE_BACKEND",
                          "MORROW_ANALYTICS_INLINE_MAX_ROWS", "MORROW_ANALYTICS_SNAPSHOT_INTERVAL_SECONDS")}
        os.environ["MORROW_SCANNER_DB"] = os.path.join(self.tmp, "snap.db")
        os.environ["MORROW_MAIN_DB_BACKEND"] = "sqlite"
        os.environ["MORROW_FEATURE_STORE_BACKEND"] = "sqlite"
        import importlib

        import db as db_module
        importlib.reload(db_module)
        db_module.init_db()
        from services import analytics_snapshots, platform_analytics, security_journal
        security_journal.init_tables()
        analytics_snapshots.init_tables()
        platform_analytics.clear_cache()
        self.snapshots = analytics_snapshots
        self.pa = platform_analytics
        return self

    def __exit__(self, *exc):
        import shutil
        self.pa.clear_cache()
        for key, value in self.previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestAnalyticsOverviewSnapshots(unittest.TestCase):
    """The overview is precomputed and served from storage, with the instant it was computed.

    Its cache TTL was 20 seconds against a computation that took 30-250 seconds on a 2M-row
    journal, so the entry was stale before it could ever be served: every request recomputed, and
    the background warmer looped over four multi-minute aggregations forever.
    """

    def test_a_read_stores_a_snapshot_and_reports_when_it_was_computed(self):
        with _SnapshotFixture() as fix:
            payload = fix.snapshots.serve("24h")
            self.assertEqual(payload["range"], "24h")
            self.assertTrue(payload["as_of"], "the response must say when its numbers were computed")
            self.assertEqual(payload["snapshot"]["state"], "fresh")
            self.assertIsNotNone(fix.snapshots.read("24h"))

    def test_the_response_contract_is_unchanged(self):
        with _SnapshotFixture() as fix:
            served = fix.snapshots.serve("7d")
            direct = fix.pa.overview("7d")
            self.assertEqual(set(direct) - set(served), set(),
                             "serving from a snapshot must not drop a field the console reads")
            for key in ("api_version", "range", "bucket"):
                self.assertEqual(served[key], direct[key])
            self.assertEqual(set(served["kpis"]), set(direct["kpis"]))
            self.assertEqual(set(served["series"]), set(direct["series"]))

    def test_a_second_read_inside_the_interval_does_not_recompute(self):
        with _SnapshotFixture() as fix:
            calls = {"n": 0}
            original = fix.pa.overview

            def counted(range_key):
                calls["n"] += 1
                return original(range_key)

            fix.pa.overview = counted
            try:
                fix.snapshots.serve("24h")
                first = calls["n"]
                fix.snapshots._read_cache.clear()  # force the stored row to be re-read
                fix.snapshots.serve("24h")
            finally:
                fix.pa.overview = original
            self.assertEqual(first, 1)
            self.assertEqual(calls["n"], 1, "a fresh snapshot must be served, not recomputed")

    def test_a_cold_read_on_a_large_journal_answers_without_computing(self):
        """The load test's finding: a cold call must be cheap, not a multi-minute aggregation."""
        with _SnapshotFixture() as fix:
            os.environ["MORROW_ANALYTICS_INLINE_MAX_ROWS"] = "0"  # "this journal is too big to do inline"
            fix.snapshots._inline_probe.clear()
            calls = {"n": 0}
            original = fix.pa.overview

            def counted(range_key):
                calls["n"] += 1
                return original(range_key)

            fix.pa.overview = counted
            original_enabled = fix.snapshots.enabled
            fix.snapshots.enabled = lambda: False  # no background thread inside the test
            try:
                payload = fix.snapshots.serve("90d")
            finally:
                fix.pa.overview = original
                fix.snapshots.enabled = original_enabled
            self.assertEqual(calls["n"], 0, "a cold read must not aggregate on the request")
            self.assertEqual(payload["snapshot"]["state"], "pending")
            self.assertIsNone(payload["as_of"])
            self.assertTrue(any(u["metric"] == "overview" for u in payload["unavailable"]))
            self.assertTrue(all(item["value"] is None for item in payload["kpis"].values()),
                            "a snapshot that does not exist yet reports null, never zero")
            self.assertEqual(len(payload["series"]["requests"]), 90)

    def test_the_pending_payload_carries_every_kpi_the_real_one_does(self):
        with _SnapshotFixture() as fix:
            real = fix.pa.overview("24h")
            pending = fix.snapshots._pending_payload("24h")
            self.assertEqual(set(pending["kpis"]), set(real["kpis"]))
            self.assertEqual(set(pending["series"]), set(real["series"]))
            self.assertEqual(set(pending["top"]), set(real["top"]))

    def test_clearing_the_cache_drops_the_stored_snapshot(self):
        with _SnapshotFixture() as fix:
            fix.snapshots.serve("24h")
            self.assertIsNotNone(fix.snapshots.read("24h"))
            fix.pa.clear_cache()
            self.assertIsNone(fix.snapshots.read("24h"))

    def test_the_warmer_no_longer_loops_over_the_aggregation(self):
        import inspect

        from services import platform_analytics

        src = inspect.getsource(platform_analytics.warm_overviews)
        self.assertNotIn("overview(key)", src,
                         "warm_overviews must delegate to the rate-limited snapshot refresher")
        self.assertIn("request_refresh", src)


# ── 10. Retention keeps pace ─────────────────────────────────────────────────


class _JournalFixture:
    def __init__(self, rows=20000, age_days=60):
        self.rows, self.age_days = rows, age_days

    def __enter__(self):
        self.tmp = tempfile.mkdtemp(prefix="pq-journal-")
        self.previous = {k: os.environ.get(k) for k in
                         ("MORROW_SCANNER_DB", "MORROW_MAIN_DB_BACKEND", "MORROW_FEATURE_STORE_BACKEND",
                          "MORROW_TRAFFIC_RETENTION_DAYS", "MORROW_TRAFFIC_ROLLUP_HOLDBACK_DAYS",
                          "MORROW_USAGE_ROLLUPS_ENABLED")}
        os.environ["MORROW_SCANNER_DB"] = os.path.join(self.tmp, "journal.db")
        os.environ["MORROW_MAIN_DB_BACKEND"] = "sqlite"
        os.environ["MORROW_FEATURE_STORE_BACKEND"] = "sqlite"
        os.environ["MORROW_TRAFFIC_RETENTION_DAYS"] = "7"
        os.environ["MORROW_TRAFFIC_ROLLUP_HOLDBACK_DAYS"] = "0"
        os.environ["MORROW_USAGE_ROLLUPS_ENABLED"] = "0"
        import importlib

        import db as db_module
        importlib.reload(db_module)
        db_module.init_db()
        from services import security_journal
        importlib.reload(security_journal)
        self.sj = security_journal
        security_journal.init_tables()
        self.seed(self.rows, self.age_days)
        return self

    def seed(self, rows, age_days):
        import db_feature_store as store
        stamp = (datetime.now(UTC) - timedelta(days=age_days)).isoformat(
            timespec="microseconds").replace("+00:00", "Z")
        with store.feature_conn() as conn:
            conn.executemany(
                "INSERT INTO platform_request_events (id, created_at, organization_id, actor_id,"
                " actor_role, source_ip, method, path, status_code, duration_ms, user_agent,"
                " authenticated) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                [(uuid.uuid4().hex, stamp, "org-a", "u", "viewer", "127.0.0.1", "GET", "/assets",
                  200, 1.0, "Chrome", 1) for _ in range(rows)])
            conn.commit()

    def count(self):
        import db_feature_store as store
        with store.feature_conn() as conn:
            return int(conn.execute("SELECT COUNT(*) FROM platform_request_events").fetchone()[0])

    def __exit__(self, *exc):
        import shutil
        for key, value in self.previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestRetentionDrainsTheBacklog(unittest.TestCase):
    """One 5,000-row batch per 60-second tick is a ceiling of 5,000 rows a minute.

    The load test measured the journal draining at 2,350 rows a minute against 5,000 arriving,
    with a single DELETE taking 18.9 s -- so a retention change, or a restore from an older
    backup, carried the excess for most of a day.
    """

    def test_one_pass_drains_a_backlog_several_batches_deep(self):
        with _JournalFixture(rows=20000) as fix:
            self.assertEqual(fix.count(), 20000)
            result = fix.sj.prune()
            self.assertEqual(fix.count(), 0, "the pass must not stop after one 5,000-row batch")
            self.assertEqual(result["traffic"], 20000)
            self.assertFalse(result["backlog"], "nothing expired is left, so there is no backlog")

    def test_a_pass_that_runs_out_of_budget_says_so(self):
        with _JournalFixture(rows=20000) as fix:
            result = fix.sj.prune(budget_seconds=0.0)
            self.assertTrue(result["backlog"], "the caller has to know to come straight back")
            self.assertEqual(fix.count(), 20000)

    def test_the_batch_size_adapts_to_how_long_a_delete_takes(self):
        from services import security_journal as sj

        sj._prune_batch.clear()
        sj._record_batch("traffic", 5000, 0.1)    # quick: grow
        self.assertEqual(sj._prune_batch_size("traffic"), 10000)
        sj._record_batch("traffic", 10000, 30.0)  # slow: back off
        self.assertEqual(sj._prune_batch_size("traffic"), 5000)
        for _ in range(20):
            sj._record_batch("traffic", sj._prune_batch_size("traffic"), 30.0)
        self.assertEqual(sj._prune_batch_size("traffic"), sj._PRUNE_BATCH_MIN)
        sj._prune_batch.clear()

    def test_the_maintenance_loop_comes_straight_back_while_there_is_a_backlog(self):
        import inspect

        import app

        src = inspect.getsource(app._lifespan)
        self.assertIn('await asyncio.sleep(1 if backlog else 60)', src)


class TestRetentionAndRollupWindowsAgree(unittest.TestCase):
    """Raw retention was clamped to 30 days while the analytics offer a 90-day range, and the
    pruner deleted a day's raw rows before the daily rollup could aggregate them -- so days 31-90
    were permanently unrollable and permanently unanswerable."""

    def test_the_traffic_ceiling_reaches_the_longest_analytics_range(self):
        from services import platform_analytics, security_journal

        longest = max(count if bucket == "day" else count / 24.0
                      for bucket, count in platform_analytics.RANGES.values())
        self.assertGreaterEqual(security_journal.RETENTION_LIMITS["traffic"][1], longest)

    def test_the_configured_value_is_still_clamped(self):
        from services import security_journal

        previous = os.environ.get("MORROW_TRAFFIC_RETENTION_DAYS")
        try:
            os.environ["MORROW_TRAFFIC_RETENTION_DAYS"] = "9999"
            self.assertEqual(security_journal._days("traffic"),
                             security_journal.RETENTION_LIMITS["traffic"][1])
            os.environ["MORROW_TRAFFIC_RETENTION_DAYS"] = "0"
            self.assertEqual(security_journal._days("traffic"), 1)
        finally:
            if previous is None:
                os.environ.pop("MORROW_TRAFFIC_RETENTION_DAYS", None)
            else:
                os.environ["MORROW_TRAFFIC_RETENTION_DAYS"] = previous

    def test_a_day_the_rollup_has_not_aggregated_is_not_deleted_yet(self):
        """Retention used to delete a day's raw rows before the rollup could aggregate them, so
        days past raw retention were permanently unrollable *and* permanently unanswerable -- the
        reason the 90-day analytics range reported "unknown" for two thirds of its span."""
        with _JournalFixture(rows=0) as fix:
            os.environ["MORROW_USAGE_ROLLUPS_ENABLED"] = "1"
            os.environ["MORROW_TRAFFIC_ROLLUP_HOLDBACK_DAYS"] = "30"
            from services import usage_rollups
            # Two whole days past retention. The day the oldest surviving row falls in may have
            # been partly pruned already, so only the days after it are known to be complete.
            fix.seed(40, 21)
            fix.seed(60, 20)
            fix.seed(50, 19)
            usage_rollups.init_tables()
            self.assertIsNotNone(usage_rollups.unrolled_floor(),
                                 "a closed day with raw rows and no rollup is unrolled")
            fix.sj.prune()
            self.assertEqual(fix.count(), 110,
                             "the whole days waiting to be rolled up must survive; only the "
                             "boundary day, which may already be partial, goes")
            usage_rollups.run()
            self.assertIsNone(usage_rollups.unrolled_floor())
            fix.sj.prune()
            self.assertEqual(fix.count(), 0, "once rolled up, the raw rows go")

    def test_the_holdback_is_capped_so_a_broken_rollup_cannot_grow_the_journal(self):
        with _JournalFixture(rows=100, age_days=60) as fix:
            os.environ["MORROW_USAGE_ROLLUPS_ENABLED"] = "1"
            os.environ["MORROW_TRAFFIC_ROLLUP_HOLDBACK_DAYS"] = "3"
            from services import usage_rollups
            usage_rollups.init_tables()
            # The rollup has aggregated nothing, so every day is "waiting"; the cap still applies.
            fix.sj.prune()
            self.assertEqual(fix.count(), 0,
                             "rows more than retention + holdback days old are deleted regardless")

    def test_a_day_whose_rows_vanish_mid_pass_is_never_rolled_up_as_zero(self):
        """The pruner deletes from the old end of the journal while a long backfill reads it.

        A pass that starts when day D is complete used to reach day D minutes later, after the
        pruner had removed it, and roll it up as **zero requests** -- a wrong number stored as
        fact, which is the one thing the rollup must never do. Caught on a 2M-row journal: the
        first pass rolled 73 days, of which 60 had already been deleted. The completeness floor is
        re-read before every day.
        """
        with _JournalFixture(rows=0) as fix:
            os.environ["MORROW_USAGE_ROLLUPS_ENABLED"] = "1"
            from services import usage_rollups
            fix.seed(30, 9)
            fix.seed(30, 8)
            usage_rollups.init_tables()

            # The pruner empties the older days while the pass is in flight: the completeness
            # floor is behind day 9 when the pass starts and past it by the time the pass gets
            # there. The first read is what rollup_start() uses; the second is the re-read.
            today = usage_rollups.day_floor(datetime.now(UTC))
            # Two reads happen before the loop (rollup_start, then the pass's own start_floor) and
            # both see the journal intact; every read inside the loop sees it pruned back to day 8.
            answers = [today - timedelta(days=10), today - timedelta(days=10),
                       today - timedelta(days=8)]
            original = usage_rollups._complete_from

            def moving_floor(now):
                return answers.pop(0) if len(answers) > 1 else answers[0]

            usage_rollups._complete_from = moving_floor
            try:
                result = usage_rollups.run()
            finally:
                usage_rollups._complete_from = original

            self.assertGreaterEqual(result["skipped_partial"], 1,
                                    "a day the pruner had reached must be skipped, not rolled")
            rolled = {r["day"] for r in result["rolled"]}
            gone = usage_rollups.day_key(usage_rollups.day_floor(datetime.now(UTC)) - timedelta(days=9))
            self.assertNotIn(gone, rolled,
                             "a day whose raw rows were deleted mid-pass must not become a rollup row")
            import db_feature_store as store
            with store.feature_conn() as conn:
                stored = conn.execute("SELECT requests FROM platform_usage_rollup_days WHERE day = ?",
                                      (gone,)).fetchone()
            self.assertIsNone(stored,
                              "a day that had traffic must be absent from the rollup -- unknown -- "
                              "rather than present with zero requests")
            # The day that was still complete is rolled, with its real count.
            kept = usage_rollups.day_key(usage_rollups.day_floor(datetime.now(UTC)) - timedelta(days=8))
            with store.feature_conn() as conn:
                row = conn.execute("SELECT requests FROM platform_usage_rollup_days WHERE day = ?",
                                   (kept,)).fetchone()
            self.assertEqual(int(row[0]), 30)

    def test_the_rollup_starts_from_the_oldest_raw_row_not_the_retention_cutoff(self):
        with _JournalFixture(rows=50, age_days=40):
            os.environ["MORROW_USAGE_ROLLUPS_ENABLED"] = "1"
            from services import usage_rollups
            usage_rollups.init_tables()
            start = usage_rollups.rollup_start()
            oldest = datetime.now(UTC) - timedelta(days=40)
            self.assertLessEqual(start, usage_rollups.day_floor(oldest) + timedelta(days=1),
                                 "a restored or over-retained journal has to be rolled from its "
                                 "oldest row, or those days are never answerable")


# ── 11. The audit write is cheap, ordered, chained and still fails closed ────


class TestAuditQueue(unittest.TestCase):
    """Every authorized read wrote an audit entry synchronously: a SELECT for the previous hash,
    an INSERT and a COMMIT, one extra transaction per read. Routine allow records are now written
    by one background writer, in order; everything else is still written on the request."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pq-audit-")
        self.previous = os.environ.get("MORROW_SCANNER_DB")
        os.environ["MORROW_SCANNER_DB"] = os.path.join(self.tmp, "audit.db")
        os.environ.pop("MORROW_MAIN_DB_BACKEND", None)
        import importlib

        import db as db_module
        self.db = importlib.reload(db_module)
        self.db.init_db()
        from services import audit_queue
        importlib.reload(audit_queue)
        self.queue = audit_queue
        self.token = self.db.set_current_organization_id("org-a")

    def tearDown(self):
        import shutil
        self.db.reset_current_organization_id(self.token)
        if self.previous is None:
            os.environ.pop("MORROW_SCANNER_DB", None)
        else:
            os.environ["MORROW_SCANNER_DB"] = self.previous
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _entry(self, n):
        return {"actor_id": "u%d" % n, "actor_role": "viewer", "action": "read.%d" % n,
                "resource_type": "organization", "resource_id": "*", "decision": "allow",
                "reason": "", "details": {}}

    def test_a_queued_entry_is_written_and_read_back(self):
        self.assertTrue(self.queue.submit("org-a", self._entry(1)))
        rows = self.db.list_audit_logs(limit=50)  # flushes first
        self.assertEqual([r["action"] for r in rows], ["read.1"])

    def test_the_chain_stays_linked_and_in_order(self):
        for n in range(8):
            self.assertTrue(self.queue.submit("org-a", self._entry(n)))
        rows = sorted(self.db.list_audit_logs(limit=50), key=lambda r: r["id"])
        self.assertEqual([r["action"] for r in rows], ["read.%d" % n for n in range(8)])
        previous = ""
        for row in rows:
            self.assertEqual(row["prev_hash"], previous, "the chain must not fork or skip")
            previous = row["entry_hash"]

    def test_a_full_queue_tells_the_caller_to_write_it_itself(self):
        original = self.queue.QUEUE_MAX
        self.queue.QUEUE_MAX = 2
        try:
            with self.queue._lock:
                self.queue._pending.extend([("org-a", self._entry(0))] * 2)
            self.assertFalse(self.queue.submit("org-a", self._entry(1)),
                             "a full queue must fail closed to a synchronous write, never drop")
        finally:
            self.queue.QUEUE_MAX = original
            with self.queue._lock:
                self.queue._pending.clear()

    def test_a_failed_flush_keeps_every_entry_and_turns_writes_synchronous(self):
        import db as db_module

        original = db_module.append_audit_log

        def boom(**_kw):
            raise RuntimeError("database is gone")

        for n in range(3):
            self.queue.submit("org-a", self._entry(n))
        db_module.append_audit_log = boom
        try:
            self.queue.flush()
        finally:
            db_module.append_audit_log = original
        self.assertTrue(self.queue.degraded(), "after a failure every caller writes synchronously")
        self.assertFalse(self.queue.submit("org-a", self._entry(9)))
        self.assertEqual(len(self.queue._pending), 3, "nothing may be dropped")
        self.assertEqual(self.queue.flush(), 3, "and everything is written once it can be")
        self.assertFalse(self.queue.degraded())
        self.assertEqual(len(self.db.list_audit_logs(limit=50)), 3)

    def test_disabling_deferred_writes_makes_every_caller_synchronous(self):
        previous = os.environ.get("MORROW_AUDIT_DEFERRED_WRITES")
        os.environ["MORROW_AUDIT_DEFERRED_WRITES"] = "0"
        try:
            self.assertFalse(self.queue.submit("org-a", self._entry(1)))
        finally:
            if previous is None:
                os.environ.pop("MORROW_AUDIT_DEFERRED_WRITES", None)
            else:
                os.environ["MORROW_AUDIT_DEFERRED_WRITES"] = previous

    def test_concurrent_appends_do_not_fork_the_chain(self):
        errors = []

        def write(n):
            token = self.db.set_current_organization_id("org-a")
            try:
                self.db.append_audit_log(actor_id="u", actor_role="viewer", action="concurrent.%d" % n,
                                         resource_type="organization", resource_id="*")
            except Exception as exc:  # pragma: no cover - surfaced by the assertion below
                errors.append(exc)
            finally:
                self.db.reset_current_organization_id(token)

        threads = [threading.Thread(target=write, args=(n,)) for n in range(12)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        rows = sorted(self.db.list_audit_logs(limit=100), key=lambda r: r["id"])
        hashes = [r["entry_hash"] for r in rows]
        self.assertEqual(len(set(hashes)), len(hashes))
        self.assertEqual([r["prev_hash"] for r in rows], [""] + hashes[:-1],
                         "two concurrent appends must not read the same previous hash")


class TestAuditSeverity(unittest.TestCase):
    """A refusal, a write and a break-glass use are never deferred."""

    def test_only_safe_methods_defer(self):
        import app

        self.assertEqual(set(app._AUDIT_DEFERRABLE_METHODS), {"GET", "HEAD", "OPTIONS"})

    def test_require_role_defers_only_the_allow_record_of_a_read(self):
        import inspect

        import app

        src = inspect.getsource(app._require_role)
        allow = src[src.rindex('decision="allow"'):]
        self.assertIn("defer=request.method.upper() in _AUDIT_DEFERRABLE_METHODS", allow)
        for deny in src.split('decision="deny"')[1:]:
            self.assertNotIn("defer=", deny[:deny.index("raise HTTPException")],
                             "a denial is never deferred")

    def test_a_deferred_entry_falls_back_to_a_synchronous_write(self):
        import app
        from services import audit_queue

        calls = {"append": 0}
        original_submit, original_append = audit_queue.submit, app.append_audit_log
        audit_queue.submit = lambda org, entry: False  # the writer is unhealthy

        def append(**_kw):
            calls["append"] += 1

        app.append_audit_log = append
        try:
            class _Request:
                method = "GET"
                headers = {}
            app._audit_event(_Request(), action="a", resource_type="organization", defer=True,
                             actor={"actor_id": "u", "actor_role": "viewer"})
        finally:
            audit_queue.submit, app.append_audit_log = original_submit, original_append
        self.assertEqual(calls["append"], 1, "a refused deferral must be written on the request")


class TestBreakGlassIsNeverLost(unittest.TestCase):
    """The load test caught a break-glass operator access going unrecorded because the database
    had momentarily dropped its connections. An audit record that is best-effort is not one."""

    class _Request:
        method = "POST"
        headers = {"user-agent": "probe"}
        client = None

        class url:
            path = "/platform/customers"

    def test_a_transient_failure_is_retried(self):
        from services import operator_auth

        attempts = {"n": 0}

        def record(*_a, **_kw):
            attempts["n"] += 1
            if attempts["n"] < 2:
                raise RuntimeError("InterfaceError")

        operator_auth._BREAK_GLASS_SEEN.clear()
        operator_auth._audit_break_glass(self._Request(), {"role": "owner"}, record)
        self.assertEqual(attempts["n"], 2, "a database blink must not lose the record")

    def test_an_access_that_cannot_be_recorded_is_refused(self):
        from fastapi import HTTPException

        from services import operator_auth

        def always_fails(*_a, **_kw):
            raise RuntimeError("PoolError")

        operator_auth._BREAK_GLASS_SEEN.clear()
        with self.assertRaises(HTTPException) as caught:
            operator_auth._audit_break_glass(self._Request(), {"role": "owner"}, always_fails)
        self.assertEqual(caught.exception.status_code, 503)
        self.assertEqual(caught.exception.detail["code"], "break_glass_not_auditable")
        self.assertNotIn(("POST", "/platform/customers"), operator_auth._BREAK_GLASS_SEEN,
                         "a use that was not recorded must not suppress the next attempt")


# ── 12. /platform/search ─────────────────────────────────────────────────────


class TestSearchIsIndexedAndCached(unittest.TestCase):
    """The only analytics endpoint with no cache, and every predicate a leading-wildcard LIKE."""

    def test_every_searched_column_has_a_trigram_index_declared(self):
        import inspect

        from services import platform_analytics as pa

        src = inspect.getsource(pa.search)
        declared = {(table, column) for table, columns in pa.SEARCH_TRIGRAM_COLUMNS for column in columns}
        for table, columns in (("organizations", ("id", "name")),
                               ("morrow_users", ("email", "full_name", "id")),
                               ("organization_memberships", ("email", "display_name", "user_id")),
                               ("platform_api_keys", ("name", "prefix", "id")),
                               ("platform_announcements", ("title", "body")),
                               ("platform_autopatches", ("title", "repo_full_name", "issue_type")),
                               ("feedback", ("message", "email", "category"))):
            self.assertIn(table, src, "search() no longer reads %s" % table)
            for column in columns:
                self.assertIn((table, column), declared,
                              "%s.%s is searched with a LIKE and has no trigram index" % (table, column))

    def test_the_index_pass_analyses_the_table_it_indexed(self):
        import inspect

        from services import platform_analytics as pa

        src = inspect.getsource(pa.apply_indexes)
        self.assertIn("ANALYZE", src,
                      "an expression index has no statistics until the table is analysed, and "
                      "without them the planner picks the trigram scan even for a common term")

    def test_the_endpoint_goes_through_the_cache(self):
        import inspect

        from routers import platform_analytics as router

        src = inspect.getsource(router.create_platform_analytics_router)
        search = src[src.index("def platform_search"):src.index("# ── 5) Notifications")]
        self.assertIn("_pa.cached(", search,
                      "/platform/search was the one analytics endpoint that queried on every call")
        self.assertIn("SEARCH_TTL", search)


# ── 13. The middleware stack on cheap paths ──────────────────────────────────


class TestCheapPathsSkipPerRequestAccounting(unittest.TestCase):
    """Twelve middlewares, a Redis INCR, a slowapi Redis check, an organization-status refresh, a
    journal enqueue and a log line -- on a route that returns a constant dict."""

    def test_the_classification(self):
        import app

        for path in ("/health", "/healthz"):
            self.assertTrue(app._is_probe_path(path))
            self.assertTrue(app._is_cheap_path(path))
        for path in ("/ui/index.html", "/vendor-admin/index.js", "/favicon.ico", "/robots.txt"):
            self.assertFalse(app._is_probe_path(path))
            self.assertTrue(app._is_cheap_path(path))
        for path in ("/assets", "/platform/analytics/overview", "/health/deep", "/v1/scan"):
            self.assertFalse(app._is_cheap_path(path), path)

    def test_the_liveness_probe_carries_the_same_security_headers(self):
        import app
        from fastapi.testclient import TestClient

        with TestClient(app.app) as client:
            res = client.get("/healthz")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json(), {"status": "ok"})
        for header, value in (("x-frame-options", "DENY"),
                              ("x-content-type-options", "nosniff"),
                              ("referrer-policy", "strict-origin-when-cross-origin"),
                              ("x-permitted-cross-domain-policies", "none")):
            self.assertEqual(res.headers.get(header), value, header)

    def test_an_unknown_host_falls_through_to_the_full_stack(self):
        import app

        previous = list(app._ALLOWED_HOSTS)
        app._ALLOWED_HOSTS[:] = ["example.com"]
        try:
            self.assertFalse(app._LivenessFastPath._host_allowed([(b"host", b"evil.test")]))
            self.assertTrue(app._LivenessFastPath._host_allowed([(b"host", b"example.com:8047")]))
            app._ALLOWED_HOSTS[:] = ["*.example.com"]
            self.assertTrue(app._LivenessFastPath._host_allowed([(b"host", b"api.example.com")]))
            self.assertFalse(app._LivenessFastPath._host_allowed([(b"host", b"example.com.evil")]))
        finally:
            app._ALLOWED_HOSTS[:] = previous

    def test_the_probe_is_not_rate_limited(self):
        import app
        from fastapi.testclient import TestClient

        with TestClient(app.app) as client:
            codes = {client.get("/healthz").status_code for _ in range(60)}
        self.assertEqual(codes, {200},
                         "a load balancer must not spend a customer's rate-limit budget")

    def test_the_slowapi_route_lookup_is_memoized_and_still_correct(self):
        import app
        from slowapi.middleware import _find_route_handler

        middleware = app._MemoizedSlowAPIMiddleware(lambda scope, receive, send: None)
        scope = {"type": "http", "method": "GET", "path": "/assets", "headers": [],
                 "query_string": b"", "root_path": ""}
        expected = _find_route_handler(app.app.routes, scope)
        self.assertIs(middleware._handler_for(app.app, scope), expected)
        self.assertIs(middleware._handler_for(app.app, scope), expected)  # from the cache
        self.assertEqual(len(middleware._route_cache), 1)

    def test_the_memo_is_bounded(self):
        import app

        middleware = app._MemoizedSlowAPIMiddleware(lambda scope, receive, send: None)
        middleware._CACHE_MAX = 4
        for n in range(10):
            middleware._handler_for(app.app, {"type": "http", "method": "GET",
                                              "path": "/assets/%d" % n, "headers": [],
                                              "query_string": b"", "root_path": ""})
        self.assertLessEqual(len(middleware._route_cache), 4)


# ── 14. Test isolation: no module hands the next one its private database ────


class TestDatabaseSelectionDoesNotLeakBetweenModules(unittest.TestCase):
    """test_wave17.py failed with "no such table: morrow_users" depending only on what ran before it.

    Several module-scoped fixtures point MORROW_SCANNER_DB at a temporary file, run against it, then
    delete the file without putting the variable back. A module-scoped fixture is finalized after
    the last test's function-scoped fixtures, so conftest's per-test restore never saw it: the next
    module inherited a database the copy isolation had never seeded -- and, because db's
    schema-creation memo is keyed by path, a file that had just been deleted and recreated empty
    was treated as already migrated.
    """

    def test_conftest_restores_the_selection_after_every_module(self):
        import inspect

        import conftest

        fixture = conftest._restore_database_selection_between_modules
        marker = (getattr(fixture, "_pytestfixturefunction", None)
                  or getattr(fixture, "_fixture_function_marker", None))
        self.assertIsNotNone(marker, "the backstop has to be a fixture")
        self.assertEqual(marker.scope, "module",
                         "a function-scoped fixture is torn down before the module fixtures that "
                         "cause this, so it cannot be the backstop")
        self.assertTrue(marker.autouse)
        src = inspect.getsource(getattr(fixture, "_fixture_function", fixture))
        for key in ("MORROW_SCANNER_DB", "MORROW_MAIN_DB_BACKEND", "MORROW_FEATURE_STORE_BACKEND"):
            self.assertIn(key, inspect.getsource(conftest))
        self.assertIn("_schema_initialized_db_path", src,
                      "the schema memo is keyed by path and has to be dropped with it")

    def test_no_module_scoped_fixture_points_the_process_at_a_database_and_leaves_it_there(self):
        """A static sweep, so the next fixture written this way fails here and not in another file."""
        import ast
        import glob

        offenders = []
        for path in sorted(glob.glob(os.path.join(BACKEND, "test_*.py"))):
            try:
                tree = ast.parse(open(path, encoding="utf-8-sig").read())
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                decorators = " ".join(ast.unparse(d) for d in node.decorator_list)
                if "fixture" not in decorators:
                    continue
                if "scope='module'" not in decorators and 'scope="module"' not in decorators \
                        and "scope='session'" not in decorators and 'scope="session"' not in decorators:
                    continue
                body = ast.unparse(node)
                if "os.environ['MORROW_SCANNER_DB'] =" not in body and 'os.environ["MORROW_SCANNER_DB"] =' not in body:
                    continue
                if "monkeypatch" in decorators or "monkeypatch" in body:
                    continue  # monkeypatch undoes its own changes
                after = body.split("yield", 1)[-1]
                if "MORROW_SCANNER_DB" not in after:
                    offenders.append("%s::%s" % (os.path.basename(path), node.name))
        self.assertEqual(offenders, [], "these module-scoped fixtures set MORROW_SCANNER_DB and never "
                                        "put it back, so the next test module inherits their "
                                        "private database: %s" % offenders)


if __name__ == "__main__":
    unittest.main()


def test_no_api_route_is_treated_as_a_cheap_static_path():
    """The cheap-path fast lane skips organization context, both rate limiters and the traffic
    journal. It may only ever match liveness probes and the real StaticFiles mounts: "/assets/" was
    once listed as static, which served the customer asset API with no tenant resolved."""
    import app as application
    from starlette.routing import Mount

    mounted = {str(r.path).rstrip("/") + "/" for r in application.app.routes if isinstance(r, Mount)}
    for prefix in application._STATIC_PATH_PREFIXES:
        assert prefix in mounted, f"{prefix} is treated as static but nothing mounts it"

    offenders = []
    for route in application.app.routes:
        path = getattr(route, "path", "")
        if isinstance(route, Mount) or not path.startswith("/"):
            continue
        # A concrete sample of the route, so "/assets/{key}" is judged the way a request is.
        sample = re.sub(r"\{[^}]+\}", "sample", path)
        allowed = application._PROBE_PATHS | application._STATIC_FILE_PATHS
        if application._is_cheap_path(sample) and sample not in allowed:
            offenders.append(path)
    assert not offenders, f"API routes skipping per-request accounting: {sorted(set(offenders))}"
