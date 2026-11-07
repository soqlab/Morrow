"""Regressions from the 100,000-asset measurements (docs/SCALE.md, "100,000 assets: the fixes").

asset_scan_latest (one row per asset: its newest scan_results row plus the certificate and key-map
fields of the full result), scan_headers (SQLite: every scans column but results_json), the trigram
search index, and the SQL counters behind /telemetry/kpis. Each test checks the new read against
the read it replaced, on a database small enough to compute the old answer.

The Postgres class is skipped unless MORROW_TEST_PG_DSN names a disposable server.
"""
import importlib
import os
import sqlite3
import sys
import tempfile
import unittest
import uuid
from datetime import datetime, timedelta, timezone

import pytest

BACKEND = os.path.dirname(os.path.abspath(__file__))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

PG_DSN = os.getenv("MORROW_TEST_PG_DSN", "").strip()
UTC = timezone.utc
NOW = datetime.now(UTC).replace(microsecond=0)

# The read latest_scan_facts_for_org made before asset_scan_latest existed (SQLite).
_OLD_NEWEST_SQL = """
    SELECT {cols} FROM scan_results sr
    WHERE sr.organization_id = ?
      AND NOT EXISTS (
          SELECT 1 FROM scan_results n
          WHERE n.organization_id = sr.organization_id AND n.asset_key = sr.asset_key
            AND (n.scanned_at > sr.scanned_at OR (n.scanned_at = sr.scanned_at AND n.id > sr.id)))
    {search}
    ORDER BY sr.scanned_at DESC, sr.id DESC
"""


def _result(n, *, days=None, nested=False, raw=None, error=False, key=("RSA", 2048), tls="TLSv1.2",
            host_suffix=".example.com", risk="high"):
    host = "h%03d%s" % (n, host_suffix)
    r = {"host": host, "port": 443 if n % 4 else 8443, "risk": risk, "quantum_risk_score": float(n % 7),
         "findings": [{"id": "f"}] * (n % 3), "tls_version": tls, "key_type": key[0], "cert_key_type": key[0],
         "cert_key_bits": key[1], "sig_algorithm": "sha256WithRSAEncryption",
         "cert_issuer": "CN=Issuer %d" % (n % 5), "cert_subject": "CN=" + host}
    if error:
        r["error"] = "handshake failed"
    expiry = raw if raw is not None else ((NOW + timedelta(days=days, hours=1)).isoformat() if days is not None else None)
    if expiry is not None:
        if nested:
            r["certificate"] = {"not_after": expiry, "serial": "x"}
        else:
            r["cert_not_after"] = expiry
    return r


def _estate():
    """Results for 40 assets over three scans, with every certificate state and key-map case."""
    variants = []
    for n in range(40):
        kw = {}
        if n % 8 == 0:
            kw["days"] = -3                      # expired
        elif n % 8 == 1:
            kw["days"] = 5                       # expiring, high
        elif n % 8 == 2:
            kw.update(days=20, nested=True)      # expiring, medium, under "certificate"
        elif n % 8 == 3:
            kw["days"] = 200                     # healthy
        elif n % 8 == 4:
            kw["raw"] = "not a date"             # unknown
        elif n % 8 == 5:
            kw["raw"] = "Mon, 01 Jan 2024 00:00:00 GMT"  # RFC 2822, expired
        if n % 9 == 0:
            kw["error"] = True
        if n % 5 == 0:
            kw["host_suffix"] = ".example.de"
        if n % 6 == 0:
            kw["key"] = ("EC", 256)
        if n % 10 == 0:
            kw["risk"] = ""
        variants.append(kw)
    return variants


def _seed(db, org, *, scans=3):
    """Three scans; each later scan rescans a subset with changed facts, and the middle one is saved
    last (an older scan written after a newer one)."""
    variants = _estate()
    stamps = [NOW - timedelta(hours=30), NOW - timedelta(hours=10), NOW - timedelta(minutes=20)]
    order = [0, 2, 1]
    for s in order[:scans]:
        when = stamps[s]
        members = [n for n in range(40) if s == 0 or n % (s + 2) == 0]
        results = []
        for n in members:
            kw = dict(variants[n])
            if s == 2:
                kw["tls"] = "TLSv1.3"
            results.append(_result(n, **kw))
        if s == 1:
            results.append(dict(results[0], tls_version="TLSv1.0"))   # a duplicate inside one scan
        scan_id = "scan-%s-%d" % (org, s)
        db.save_scan_row(scan_id, "completed", when, {"total": len(results)}, "", results, {"total": len(results)})
        db.save_scan_results(scan_id, results=results, summary={"total": len(results)}, status="completed")
        db.save_scan_asset_summaries(scan_id, when.isoformat().replace("+00:00", "Z"), results)
        for n in members[:5]:
            db.upsert_asset("h%03d.example.com:%d" % (n, 443 if n % 4 else 8443), owner="o", team="Team-%d" % (n % 3),
                            environment="prod", criticality="tier-1")


class _SqliteBase(unittest.TestCase):
    ORGS = ("org-a", "org-b")

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pq-scale-reads-")
        self.previous = {k: os.environ.get(k) for k in ("MORROW_SCANNER_DB", "MORROW_MAIN_DB_BACKEND")}
        os.environ["MORROW_SCANNER_DB"] = os.path.join(self.tmp, "reads.db")
        os.environ.pop("MORROW_MAIN_DB_BACKEND", None)
        import db as db_module
        self.db = importlib.reload(db_module)
        self.db.init_db()
        for org in self.ORGS:
            token = self.db.set_current_organization_id(org)
            try:
                _seed(self.db, org)
            finally:
                self.db.reset_current_organization_id(token)
        self.token = self.db.set_current_organization_id("org-a")

    def tearDown(self):
        import shutil

        self.db.reset_current_organization_id(self.token)
        for key, value in self.previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        shutil.rmtree(self.tmp, ignore_errors=True)

    def raw(self):
        conn = sqlite3.connect(os.environ["MORROW_SCANNER_DB"])
        conn.row_factory = sqlite3.Row
        return conn

    def old_newest(self, org, term=""):
        cols = ", ".join(self.db._SCAN_FACT_COLUMNS)
        search, params = "", [org]
        if term:
            search = " AND " + self.db._SCAN_FACT_SEARCH_SQL
            params += [self.db._like_contains(term)] * self.db._SCAN_FACT_SEARCH_TERMS
        conn = self.raw()
        try:
            return [dict(r) for r in conn.execute(_OLD_NEWEST_SQL.format(cols=cols, search=search), params)]
        finally:
            conn.close()


class TestNewestRowPerAssetTable(_SqliteBase):
    def assertSameAsHistory(self):
        for org in self.ORGS:
            token = self.db.set_current_organization_id(org)
            try:
                got = self.db.latest_scan_facts_for_org(limit=5000)
            finally:
                self.db.reset_current_organization_id(token)
            self.assertEqual(got, self.old_newest(org), org)

    def test_written_by_the_scan_path_equals_the_history_walk(self):
        self.assertSameAsHistory()
        self.assertEqual(len(self.db.latest_scan_facts_for_org(limit=5000)), 40)
        self.assertEqual(len(self.db.latest_scan_facts_for_org(limit=7)), 7)

    def test_raw_sql_writers_keep_it_exact(self):
        conn = self.raw()
        conn.execute("INSERT INTO scan_results (organization_id, asset_key, scan_id, scanned_at, risk_level, quantum_score,"
                     " findings_count, pq_relevance, tls_version, key_type, sig_algorithm, owner, team, environment,"
                     " criticality) VALUES ('org-a', 'h001.example.com:443', 'raw', ?, 'low', 0, 0, '', 'TLSv1.3', 'ML-KEM',"
                     " '', '', '', '', '')", ((NOW + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),))
        conn.execute("UPDATE scan_results SET risk_level = 'critical' WHERE scan_id = 'scan-org-a-2'")
        # Retention: deleting an asset's newest row promotes the next one; deleting all removes it.
        conn.execute("DELETE FROM scan_results WHERE scan_id = 'raw'")
        conn.execute("DELETE FROM scan_results WHERE scan_id = 'scan-org-a-2'")
        conn.execute("DELETE FROM scan_results WHERE organization_id = 'org-a' AND asset_key LIKE 'h003.%'")
        conn.execute("UPDATE scan_results SET scanned_at = ? WHERE scan_id = 'scan-org-a-0' AND asset_key LIKE 'h005.%'",
                     ((NOW + timedelta(days=1)).isoformat().replace("+00:00", "Z"),))
        conn.commit()
        conn.close()
        self.assertSameAsHistory()

    def test_a_database_written_before_the_table_is_backfilled(self):
        conn = self.raw()
        expected = {r["asset_key"]: dict(r) for r in conn.execute("SELECT * FROM asset_scan_latest WHERE organization_id='org-a'")}
        conn.execute("DELETE FROM asset_scan_latest")
        conn.execute("DELETE FROM morrow_backfills")
        conn.commit()
        conn.close()
        self.db._SCHEMA_ONCE.clear()
        self.db.init_db()  # the schema step restores the facts, the startup backfill the rest
        conn = self.raw()
        got = {r["asset_key"]: dict(r) for r in conn.execute("SELECT * FROM asset_scan_latest WHERE organization_id='org-a'")}
        conn.close()
        self.assertEqual(sorted(got), sorted(expected))
        for key, row in expected.items():
            row.pop("result_id")
            other = dict(got[key])
            other.pop("result_id")
            self.assertEqual(other, row, key)
        self.assertSameAsHistory()


class TestSearchIndex(_SqliteBase):
    TERMS = ("h001", "H01", "example.de", "tlsv1.3", "unknown", "critical", "team-2", "ec", "%", "_", "h0_",
             "zz-no-match", ".com:84", "sha256withrsa", "o")

    def test_same_assets_as_the_like_walk(self):
        for term in self.TERMS:
            got = self.db.latest_scan_facts_for_org(limit=5000, text_query=term)
            self.assertEqual(got, self.old_newest("org-a", term.lower()), term)

    def test_common_terms_take_the_newest_first_walk_with_the_same_answer(self):
        cap = self.db._SEARCH_ROWID_CAP
        self.db._SEARCH_ROWID_CAP = 1
        try:
            for term in self.TERMS:
                for limit in (5000, 3):
                    got = self.db.latest_scan_facts_for_org(limit=limit, text_query=term)
                    self.assertEqual(got, self.old_newest("org-a", term.lower())[:limit], (term, limit))
        finally:
            self.db._SEARCH_ROWID_CAP = cap

    def test_the_trigram_index_serves_long_terms(self):
        conn = self.db.get_connection()
        try:
            self.assertTrue(self.db._has_asset_search_index(conn))
            plan = " | ".join(r[3] for r in conn.execute(
                "EXPLAIN QUERY PLAN SELECT rowid FROM asset_scan_latest_fts WHERE asset_scan_latest_fts MATCH ?",
                ('"h001"',)))
        finally:
            conn.close()
        self.assertIn("VIRTUAL TABLE INDEX", plan)


class TestScanHeaders(_SqliteBase):
    def test_list_scan_rows_reads_the_headers_and_matches_scans(self):
        self.db.update_scan_progress("scan-org-a-1", {"percent": 50}, status="running")
        self.db.update_scan_job("scan-org-a-1", job_id="j1", job_state="STARTED", finished_at_iso="2026-01-01T00:00:00Z")
        conn = self.raw()
        conn.execute("UPDATE scans SET summary_json = '{\"total\": 99}' WHERE id = 'scan-org-a-0'")
        conn.commit()
        cols = ", ".join(self.db._SCAN_HEADER_COLUMNS)
        scans = {r[0]: tuple(r[1:]) for r in conn.execute("SELECT id, %s FROM scans" % cols)}
        headers = {r[0]: tuple(r[1:]) for r in conn.execute("SELECT scan_id, %s FROM scan_headers" % cols)}
        conn.close()
        self.assertEqual(headers, scans)
        statements = []
        real = self.db.get_connection

        def traced():
            c = real()
            c.set_trace_callback(statements.append)
            return c

        self.db.get_connection = traced
        try:
            rows = self.db.list_scan_rows(limit=10)
        finally:
            self.db.get_connection = real
        self.assertEqual([r["id"] for r in rows], ["scan-org-a-2", "scan-org-a-1", "scan-org-a-0"])
        self.assertEqual(rows[2]["summary"], {"total": 99})
        self.assertEqual(rows[1]["job_state"], "STARTED")
        self.assertFalse([s for s in statements if "FROM scans" in s], statements)


class TestCertificateAndKeyMapReports(_SqliteBase):
    def newest_full_results(self, org):
        """{asset_key: (newest full result, scan_id, scanned_at)} the way the scan path keys them."""
        out = {}
        facts = {f["asset_key"]: f for f in self.old_newest(org)}
        token = self.db.set_current_organization_id(org)
        try:
            for key, f in facts.items():
                scan = self.db.load_scan_row(f["scan_id"])
                match = [r for r in scan["results"] if self.db._result_asset_key_sqlite(r) == key]
                out[key] = (match[-1] if match else None, f["scan_id"], f["scanned_at"])
        finally:
            self.db.reset_current_organization_id(token)
        return out

    def test_certificate_report_equals_classifying_the_newest_results(self):
        from services.crypto_governance import (build_certificate_lifecycle_report,
                                                build_certificate_lifecycle_report_from_rows)

        now = datetime.now(UTC)
        newest = self.newest_full_results("org-a")
        assets = self.db.list_assets(limit=5000)

        def latest(key):
            result, scan_id, scanned_at = newest.get(key, (None, "", ""))
            if result is None:
                return {"scan_id": scan_id, "scanned_at": scanned_at} if scan_id else {}
            return dict(result, scan_id=scan_id, scanned_at=scanned_at)

        for warning in (365, 3, 30):  # 30 last: the checks below are about it
            expected = build_certificate_lifecycle_report(assets=assets, latest_for_asset=latest, warning_days=warning)
            for limit in (5000, 7, 21, 26, 33, 38):
                data = self.db.certificate_lifecycle_rows(warning, now, limit)
                got = build_certificate_lifecycle_report_from_rows(data, warning_days=warning, now=now)
                self.assertEqual(got["summary"], expected["summary"], warning)
                strip = [{k: v for k, v in i.items() if k != "scanned_at"} for i in expected["items"]]
                self.assertEqual([{k: v for k, v in i.items() if k != "scanned_at"} for i in got["items"]],
                                 strip[:limit], (warning, limit))
                self.assertEqual(got["inventory_coverage"]["complete"], limit >= len(assets))
        self.assertEqual(sum(expected["summary"].values()), len(assets))
        self.assertTrue(all(expected["summary"][k] for k in ("expired", "expiring_soon", "healthy", "unknown")))

    def test_key_map_equals_the_map_of_the_newest_results(self):
        from services.dark_matter import build_dark_matter_map, build_dark_matter_map_from_rows

        newest = self.newest_full_results("org-a")
        expected = build_dark_matter_map([[r for r, _, _ in newest.values() if r is not None]])
        got = build_dark_matter_map_from_rows(self.db.key_map_rows(record_limit=5000))
        self.assertEqual(got["meta"], expected["meta"])
        key = lambda r: (r["host"], r["port"])  # noqa: E731
        self.assertEqual(sorted(got["key_records"], key=key), sorted(expected["key_records"], key=key))
        by_country = lambda rows: {c["country"]: c for c in rows}  # noqa: E731
        self.assertEqual(by_country(got["country_summary"]), by_country(expected["country_summary"]))
        self.assertTrue(got["coverage"]["complete"])
        short = build_dark_matter_map_from_rows(self.db.key_map_rows(record_limit=3))
        self.assertEqual(len(short["key_records"]), 3)
        self.assertFalse(short["coverage"]["complete"])

    def test_reports_do_not_read_scan_json(self):
        statements = []
        real = self.db.get_connection

        def traced():
            c = real()
            c.set_trace_callback(statements.append)
            return c

        self.db.get_connection = traced
        try:
            self.db.certificate_lifecycle_rows(30, datetime.now(UTC), 5000)
            self.db.key_map_rows()
            self.db.asset_latest_evidence(["h001.example.com:443"])
        finally:
            self.db.get_connection = real
        self.assertTrue(statements)
        self.assertFalse([s for s in statements if "results_json" in s or "FROM scans" in s], statements)


class TestHndlCoversTheEstate(_SqliteBase):
    def old_inputs(self):
        """The asset inputs /hndl/dashboard built per asset before (without its 1,000 cap)."""
        assets = self.db.list_assets(limit=5000)
        latest = self.db.latest_scan_results_for_assets([a["asset_key"] for a in assets])
        out = []
        for a in assets:
            ak = a["asset_key"]
            host, _, port = ak.partition(":")
            row = latest.get(ak) or {}
            dt = datetime.fromisoformat(str(a["updated_at"]).replace("Z", "+00:00"))
            out.append({"asset_key": ak, "host": host, "port": int(port or 443),
                        "tls_version": str(row.get("tls_version") or ""), "cipher_name": str(row.get("cipher_name") or ""),
                        "key_type": str(row.get("key_type") or ""), "key_bits": int(row.get("key_bits") or 0),
                        "key_exchange": str(row.get("key_exchange") or ""),
                        "first_scan_days_ago": max(30, (datetime.now(UTC) - dt).days),
                        "owner": str(a.get("owner") or ""), "environment": str(a.get("environment") or "")})
        return out

    def test_estate_dashboard_and_timeline_equal_the_per_asset_model(self):
        from services.hndl import (compute_hndl_timeline, compute_hndl_timeline_for_estate,
                                   compute_org_hndl_dashboard, compute_org_hndl_dashboard_for_estate)

        rows = self.db.hndl_asset_inputs(datetime.now(UTC))
        self.assertEqual(len(rows), len(self.db.list_assets(limit=5000)))
        old = self.old_inputs()
        for year in (2027, 2031, None):
            self.assertEqual(compute_org_hndl_dashboard_for_estate(rows, q_day_year=year),
                             compute_org_hndl_dashboard(old, q_day_year=year), year)
        for a, b in zip(compute_hndl_timeline_for_estate(rows), compute_hndl_timeline(old)):
            self.assertEqual({k: a[k] for k in ("year", "critical_count", "high_count")},
                             {k: b[k] for k in ("year", "critical_count", "high_count")})
            self.assertAlmostEqual(a["total_exposure_usd"], b["total_exposure_usd"], places=1)


class TestTelemetryKpis(_SqliteBase):
    def test_sql_counters_equal_the_event_list_on_a_small_database(self):
        import app

        for org in self.ORGS:
            old = app._telemetry_real_kpis_from_events(org)
            new = app._telemetry_real_kpis(org)
            for key in ("scans_last_hour", "canary_trips_24h", "critical_findings_24h", "hndl_alerts_24h",
                        "alerts_fired_24h", "runtime_proofs_24h", "last_scan_host", "last_scan_risk",
                        "evidence_event_count", "evidence_sources"):
                self.assertEqual(new[key], old[key], (org, key))
        self.assertEqual(new["scans_last_hour"], 1)
        self.assertGreater(new["critical_findings_24h"], 0)


# ── Postgres ────────────────────────────────────────────────────────────────

@pytest.mark.skipif(not PG_DSN, reason="set MORROW_TEST_PG_DSN to run against a real Postgres")
class TestPostgresReads(unittest.TestCase):
    """The same answers from the Postgres schema, triggers and trigram search."""

    @classmethod
    def setUpClass(cls):
        import psycopg2

        cls.dbname = "pq_scale_reads_%s" % uuid.uuid4().hex[:8]
        admin = psycopg2.connect(PG_DSN)
        admin.autocommit = True
        with admin.cursor() as cur:
            cur.execute("CREATE DATABASE %s" % cls.dbname)
        admin.close()
        cls.dsn = "%s/%s" % (PG_DSN.rsplit("/", 1)[0], cls.dbname)
        cls.previous = {k: os.environ.get(k) for k in ("MORROW_PRODUCT_DATABASE_URL", "MORROW_MAIN_DB_BACKEND",
                                                       "MORROW_SCANNER_DB")}
        cls.tmp = tempfile.mkdtemp(prefix="pq-scale-reads-pg-")
        os.environ["MORROW_SCANNER_DB"] = os.path.join(cls.tmp, "sidecar.db")
        os.environ["MORROW_PRODUCT_DATABASE_URL"] = cls.dsn
        os.environ["MORROW_MAIN_DB_BACKEND"] = "postgres"
        import db_postgres
        db_postgres.close_pools()
        import db as db_module
        cls.db = importlib.reload(db_module)
        cls.db.init_db()
        for org in ("org-a", "org-b"):
            token = cls.db.set_current_organization_id(org)
            try:
                _seed(cls.db, org)
            finally:
                cls.db.reset_current_organization_id(token)
        cls.pg = db_postgres

    @classmethod
    def tearDownClass(cls):
        import shutil

        import psycopg2

        cls.pg.close_pools()
        for key, value in cls.previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        admin = psycopg2.connect(PG_DSN)
        admin.autocommit = True
        with admin.cursor() as cur:
            cur.execute("DROP DATABASE IF EXISTS %s WITH (FORCE)" % cls.dbname)
        admin.close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        self.token = self.db.set_current_organization_id("org-a")

    def tearDown(self):
        self.db.reset_current_organization_id(self.token)

    def history(self, term=""):
        """The DISTINCT ON read pg_latest_scan_facts_for_org made before asset_scan_latest."""
        cols = ", ".join(self.pg._SCAN_FACT_COLUMNS)
        where, params = "", []
        if term:
            pattern = "%" + term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            where = (" WHERE asset_key ILIKE %s OR key_type ILIKE %s OR sig_algorithm ILIKE %s OR tls_version ILIKE %s"
                     " OR (CASE WHEN COALESCE(risk_level, '') = '' THEN 'unknown' ELSE risk_level END) ILIKE %s"
                     " OR owner ILIKE %s OR team ILIKE %s OR environment ILIKE %s")
            params = [pattern] * 8
        from psycopg2.extras import RealDictCursor
        with self.pg.pg_product_conn(self.dsn) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    "SELECT %s FROM (SELECT DISTINCT ON (asset_key) %s, id FROM scan_results WHERE organization_id = %%s"
                    " ORDER BY asset_key, scanned_at DESC, id DESC) newest%s ORDER BY scanned_at DESC, id DESC"
                    % (cols, cols, where), ["org-a", *params])
                return [self.pg._row_to_scan_result_dict(r) for r in cur.fetchall()]

    def test_newest_rows_and_search(self):
        self.assertEqual(self.db.latest_scan_facts_for_org(limit=5000), self.history())
        for term in TestSearchIndex.TERMS:
            self.assertEqual(self.db.latest_scan_facts_for_org(limit=5000, text_query=term),
                             self.history(term.lower()), term)

    def test_trigram_index_exists(self):
        with self.pg.pg_product_conn(self.dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT indexname FROM pg_indexes WHERE tablename = 'asset_scan_latest'")
                names = {r[0] for r in cur.fetchall()}
        self.assertIn("idx_asset_scan_latest_search_trgm", names)

    def test_reports_match_sqlite_semantics(self):
        from services.crypto_governance import build_certificate_lifecycle_report_from_rows
        from services.dark_matter import build_dark_matter_map_from_rows

        now = datetime.now(UTC)
        report = build_certificate_lifecycle_report_from_rows(self.db.certificate_lifecycle_rows(30, now, 5000),
                                                              warning_days=30, now=now)
        self.assertGreaterEqual(sum(report["summary"].values()), 40)
        self.assertTrue(all(report["summary"][k] for k in ("expired", "expiring_soon", "healthy", "unknown")))
        order = [(i["severity"], i["days_remaining"]) for i in report["items"]]
        rank = {"critical": 0, "high": 1, "medium": 2, "unknown": 3, "info": 4}
        self.assertEqual(order, sorted(order, key=lambda o: (rank[o[0]], 99999 if o[1] is None else o[1])))
        km = build_dark_matter_map_from_rows(self.db.key_map_rows())
        self.assertEqual(km["meta"]["total_keys_mapped"], len(km["key_records"]))
        self.assertTrue(km["meta"]["countries_covered"] >= 1)

    def test_retention_delete_promotes_the_next_row(self):
        with self.pg.pg_product_conn(self.dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM scan_results WHERE scan_id = 'scan-org-a-2'")
        self.assertEqual(self.db.latest_scan_facts_for_org(limit=5000), self.history())


def test_postgres_schema_declares_the_table_its_triggers_and_backfill():
    import db_postgres

    ddl = " ".join(db_postgres.POSTGRES_CORE_SCHEMA_SQL)
    for needle in ("CREATE TABLE IF NOT EXISTS asset_scan_latest", "trg_scan_results_latest_ins",
                   "trg_scan_results_latest_del", "trg_scan_results_latest_upd", "idx_asset_scan_latest_org_scanned",
                   "morrow_backfills"):
        assert needle in ddl, needle
    from services.postgres_rls import ORG_SCOPED_TABLES

    assert "asset_scan_latest" in ORG_SCOPED_TABLES


def test_digest_helpers_are_pure():
    from services.asset_posture import normalized_expiry, result_extras

    assert normalized_expiry("2030-01-02T03:04:05Z") == "2030-01-02T03:04:05.000000Z"
    assert normalized_expiry("garbage") is None
    extras = result_extras({"host": "a.example.de", "port": 443, "cert_key_type": "RSA", "cert_key_bits": 2048,
                            "certificate": {"notAfter": "2030-01-02T03:04:05+01:00"}})
    assert extras["cert_expires_at"] == "2030-01-02T02:04:05.000000Z"
    assert extras["map_country"] == "DE" and extras["map_risk_score"] == 0.85 and extras["map_included"] == 1
