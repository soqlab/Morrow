"""Security metadata uses real temporary databases; test events never touch operator data."""
import importlib
import json
import logging
import os
import sqlite3
import uuid
from contextlib import contextmanager

import pytest

from services import auth_issuer, security_journal as journal
from services.log_safety import AccessLogFilter


@pytest.fixture
def database(tmp_path, monkeypatch):
    path = tmp_path / "journal.db"
    monkeypatch.setenv("MORROW_SCANNER_DB", str(path))
    monkeypatch.setenv("MORROW_FEATURE_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("MORROW_AUTH_LOG_RETENTION_DAYS", "90")
    monkeypatch.setenv("MORROW_TRAFFIC_RETENTION_DAYS", "7")
    return path


def test_durable_allowlisted_metadata(database):
    journal.record_auth("login.failure", subject="private@example.test", source_ip="192.0.2.9", user_agent="Chrome/123 token-secret")
    journal.record_request({"path": "/assets/{asset_id}?token=secret", "source_ip": "192.0.2.9", "status_code": 200,
                            "body": "private payload", "authorization": "Bearer secret", "cookie": "session=secret",
                            "user_agent": "Chrome/123 token-secret"})
    importlib.reload(journal)
    auth, requests = journal.auth_events(), journal.request_events()
    assert len(auth) == len(requests) == 1
    assert auth[0]["user_id"] == auth[0]["organization_id"] == ""
    assert len(auth[0]["subject_ref"]) == 64
    assert requests[0]["path"] == "/assets/{asset_id}"
    assert requests[0]["user_agent"] == "Chrome"
    encoded = json.dumps([auth, requests])
    for secret in ("private@example", "secret", "private payload", "authorization", "cookie"):
        assert secret not in encoded


def test_retention_hides_then_deletes_expired_rows(database):
    journal.record_auth("login.success", user={"id": "user-a", "org_id": "org-a"})
    journal.record_request({"path": "/expired"})
    with journal.store.feature_conn() as conn:
        for table in ("platform_auth_events", "platform_request_events"):
            conn.execute(f"UPDATE {table} SET created_at='2000-01-01T00:00:00.000000Z'")
        conn.commit()
    assert journal.auth_events() == journal.request_events() == []
    assert journal.login_count("1999") == 0
    assert journal.customer_login_stats() == {}
    pruned = journal.prune()
    assert (pruned["auth"], pruned["traffic"]) == (1, 1)
    again = journal.prune()
    assert (again["auth"], again["traffic"]) == (0, 0)


def test_literal_filters_counts_and_customer_stats(database):
    for path in ("/a%b", "/axb", "/a_b"):
        journal.record_request({"path": path, "source_ip": "192.0.2.8"})
    assert [r["path"] for r in journal.request_events(path_prefix="/a%", source_ip="192.0.2.8")] == ["/a%b"]
    assert journal.request_events(source_ip="192.0.2.7") == []
    for event in ("login.success", "saml.success", "refresh.success", "login.failure"):
        journal.record_auth(event, user={"id": "a", "org_id": "org-a"})
    assert journal.login_count("2000") == 2
    assert len(journal.auth_events(successful_logins=True)) == 2
    assert len(journal.auth_events(event_type="login.failure")) == 1
    assert journal.customer_login_stats()["org-a"]["active_users_7d"] == 1


def test_health_is_explicit_and_does_not_manufacture_events(database, monkeypatch, caplog):
    assert journal.health(verify_writes=True)["insert_permission_verified"]
    assert journal.auth_events() == journal.request_events() == []
    original = journal.store.feature_conn
    def broken():
        raise RuntimeError("database-password-secret")
    with monkeypatch.context() as m:
        m.setattr(journal.store, "feature_conn", broken)
        with pytest.raises(journal.JournalUnavailable):
            journal.record_auth("login.failure")
        assert journal.health()["status"] == "degraded"
    assert journal.store.feature_conn is original
    assert "database-password-secret" not in caplog.text
    journal.record_auth("login.failure")
    health = journal.health()
    assert health["status"] == "available"
    assert health["writes"]["auth"]["failed_writes"] == 1
    journal.mark_failure("retention")
    assert journal.health()["status"] == "degraded"
    journal.prune()
    assert journal.health()["status"] == "available"


def test_no_implicit_bootstrap_or_logged_password(database, monkeypatch, caplog):
    monkeypatch.delenv("MORROW_ADMIN_PASSWORD", raising=False)
    caplog.set_level(logging.INFO)
    with sqlite3.connect(database) as conn:
        auth_issuer.init_tables(conn)
        assert conn.execute("SELECT count(*) FROM morrow_users").fetchone()[0] == 0
        monkeypatch.setenv("MORROW_ADMIN_PASSWORD", "Explicit-bootstrap-password-194!")
        auth_issuer.init_tables(conn)
        assert conn.execute("SELECT count(*) FROM morrow_users").fetchone()[0] == 1
        hashed = conn.execute("SELECT password_hash FROM morrow_users").fetchone()[0]
        assert hashed.split("$")[2] == auth_issuer._dummy_hash().split("$")[2] == "12"
    assert "Explicit-bootstrap-password-194!" not in caplog.text


@pytest.mark.parametrize("password", ["short1", "no-numeric-characters", "a" * 72 + "1"])
def test_password_validation_rejects_invalid_secrets(password):
    with pytest.raises(ValueError):
        auth_issuer._validate_password_strength(password)


def test_access_log_omits_query_and_path_credentials():
    record = logging.LogRecord("uvicorn.access", 20, "", 1, '%s - "%s %s HTTP/%s" %d',
                               ("192.0.2.1:9999", "GET", "/token/secret-path?password=secret-query", "1.1", 200), None)
    assert AccessLogFilter().filter(record)
    assert "secret" not in record.getMessage()
    assert "GET" in record.getMessage() and "200" in record.getMessage()


@pytest.mark.skipif(not os.getenv("MORROW_TEST_PG_DSN"), reason="Requires a disposable Postgres test instance")
def test_postgres_runtime_without_ddl_and_read_only_failure(monkeypatch):
    import psycopg2
    from psycopg2 import sql
    from psycopg2.extensions import make_dsn
    suffix = uuid.uuid4().hex
    database, role = "journal_test_" + suffix, "journal_role_" + suffix
    admin = psycopg2.connect(os.environ["MORROW_TEST_PG_DSN"])
    admin.autocommit = True
    with admin.cursor() as cur:
        cur.execute(sql.SQL("CREATE DATABASE {} TEMPLATE template0").format(sql.Identifier(database)))
        cur.execute(sql.SQL("CREATE ROLE {} NOLOGIN NOSUPERUSER NOBYPASSRLS").format(sql.Identifier(role)))
    original = journal.store.feature_conn
    try:
        monkeypatch.setenv("MORROW_FEATURE_STORE_BACKEND", "postgres")
        monkeypatch.setattr(journal.store, "_feature_dsn", lambda: make_dsn(os.environ["MORROW_TEST_PG_DSN"], dbname=database))
        journal.init_tables()
        with original() as conn:
            conn.execute(f"GRANT USAGE ON SCHEMA public TO {role}")
            conn.execute(f"GRANT SELECT,INSERT,DELETE ON platform_auth_events,platform_request_events TO {role}")
            conn.commit()
        @contextmanager
        def restricted():
            with original() as conn:
                conn.execute(f"SET ROLE {role}")
                yield conn
        monkeypatch.setattr(journal.store, "feature_conn", restricted)
        journal._ready.discard(journal._key())
        journal.record_auth("login.success", user={"id": "a", "org_id": "org-a"})
        journal.record_auth("saml.success", user={"id": "b", "org_id": "org-b"})
        journal.record_request({"path": "/status", "source_ip": "192.0.2.8"})
        assert len(journal.auth_events()) == 2
        assert len(journal.auth_events(organization_id="org-a")) == 1
        assert journal.login_count("2000") == 2
        assert len(journal.customer_login_stats()) == 2
        assert len(journal.request_events(path_prefix="/status")) == 1
        assert journal.health(verify_writes=True)["insert_permission_verified"]
        pruned = journal.prune()
        assert (pruned["auth"], pruned["traffic"]) == (0, 0)
        with original() as conn:
            conn.execute(f"REVOKE INSERT ON platform_auth_events,platform_request_events FROM {role}")
            conn.commit()
        assert journal.health(verify_writes=True)["status"] == "degraded"
        with pytest.raises(journal.JournalUnavailable):
            journal.record_auth("login.failure")
        assert len(journal.auth_events()) == 2
    finally:
        with admin.cursor() as cur:
            cur.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(database)))
            cur.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))
        admin.close()
