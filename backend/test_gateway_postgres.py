"""Real restricted-role tests in a disposable database, never in the supplied database's tables."""
import os
import uuid
from contextlib import contextmanager

import pytest

from services import gateway
from services.postgres_rls import build_rls_sql, quote_ident


@pytest.mark.skipif(not os.getenv("PQC_TEST_PG_DSN"), reason="PQC_TEST_PG_DSN is required for real Postgres isolation tests")
def test_gateway_with_real_postgres_restricted_role(monkeypatch):
    import psycopg2
    from psycopg2.extensions import make_dsn
    from psycopg2 import sql
    import db_feature_store

    suffix = uuid.uuid4().hex
    database, role = "gateway_test_" + suffix, "gateway_role_" + suffix
    admin = psycopg2.connect(os.environ["PQC_TEST_PG_DSN"])
    admin.autocommit = True
    with admin.cursor() as cursor:
        cursor.execute(sql.SQL("CREATE DATABASE {} TEMPLATE template0").format(sql.Identifier(database)))
    try:
        with admin.cursor() as cursor:
            cursor.execute(sql.SQL("CREATE ROLE {} NOLOGIN NOSUPERUSER NOBYPASSRLS").format(sql.Identifier(role)))
        monkeypatch.setenv("PQC_FEATURE_STORE_BACKEND", "postgres")
        monkeypatch.setattr(db_feature_store, "_feature_dsn", lambda: make_dsn(os.environ["PQC_TEST_PG_DSN"], dbname=database))
        gateway.init_tables()
        with db_feature_store.feature_conn() as conn:
            conn.execute(build_rls_sql(app_role=role, tables=["gateway_sites", "gateway_history"]))
            conn.execute(f"GRANT USAGE ON SCHEMA public TO {quote_ident(role)}")
            conn.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON gateway_sites, gateway_history TO {quote_ident(role)}")
            conn.commit()

        @contextmanager
        def restricted():
            with db_feature_store.feature_conn() as conn:
                conn.execute(f"SET ROLE {quote_ident(role)}")
                yield conn

        monkeypatch.setattr(gateway, "feature_conn", restricted)
        first = gateway.create_site("tenant-a", "www.customer.com", "origin.customer.com", "admin-a")
        second = gateway.create_site("tenant-b", "www.customer.com", "origin.customer.com", "admin-b")
        assert len(gateway.list_sites("tenant-a")) == len(gateway.list_sites("tenant-b")) == 1
        with pytest.raises(gateway.GatewayError) as denied:
            gateway.get_site("tenant-b", first["id"])
        assert denied.value.status == 404
        gateway.change_policy("tenant-a", first["id"], {"retention_hours": 0}, "admin-a", "Stop retaining aggregate counters", 1)
        assert len(gateway.history("tenant-a", first["id"])) == 2
        assert len(gateway.history("tenant-b", second["id"])) == 1
        # Intentionally omit WHERE: the database, not only the API, must prevent leaks.
        with gateway.connection("tenant-b") as conn:
            assert [row["id"] for row in conn.execute("SELECT id FROM gateway_sites").fetchall()] == [second["id"]]
            assert conn.execute("UPDATE gateway_sites SET hostname='changed.customer.com' WHERE id=?", (first["id"],)).rowcount == 0
            with pytest.raises(psycopg2.errors.InsufficientPrivilege):
                conn.execute("UPDATE gateway_sites SET organization_id='tenant-a' WHERE id=?", (second["id"],))
            conn.rollback()
        with restricted() as conn:
            assert conn.execute("SELECT id FROM gateway_sites").fetchall() == [], "Missing tenant context must fail closed"
    finally:
        # Only the uniquely named database/role created by this test is removed.
        with admin.cursor() as cursor:
            cursor.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(database)))
            cursor.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))
        admin.close()
