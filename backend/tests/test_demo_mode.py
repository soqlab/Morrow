"""Public demo mode: the write allowlist, the network lock and workspace deletion."""
import socket
import sqlite3
from contextlib import closing

import pytest

from services import demo_mode as dm

ORG = "demo-1791550000-0123456789ab"
OTHER = "demo-1791550001-ba9876543210"


@pytest.mark.parametrize("method,path,allowed", [
    ("GET", "/assets", True),
    ("GET", "/ui/index.html", True),
    ("GET", "/platform/customers", False),
    ("GET", "/vendor-admin", False),
    ("GET", "/admin/orgs", False),
    ("PUT", "/assets/www.example.com:443", True),
    ("POST", "/remediations/7/approve", True),
    ("POST", "/remediations/7/create-pr", False),
    ("POST", "/scan", False),
    ("POST", "/scans", False),
    ("POST", "/scan/ssh", False),
    ("POST", "/auth/register", False),
    ("POST", "/auth/login", False),
    ("POST", "/organizations", False),
    ("POST", "/webhooks", False),
    ("POST", "/integrations/slack/test", False),
    ("POST", "/demo/start", True),
])
def test_request_policy(method, path, allowed):
    assert dm.request_allowed(method, path) is allowed


def test_synthetic_scans_only_from_the_seeder():
    # Scan ids are global; a visitor choosing another workspace's id could overwrite it.
    assert dm.request_allowed("POST", "/scans/synthetic") is False
    assert dm.request_allowed("POST", "/scans/synthetic", from_seed=True) is True


@pytest.mark.parametrize("host,local", [
    ("127.0.0.1", True), ("::1", True), ("localhost", True), ("0.0.0.0", True),
    ("1.1.1.1", False), ("10.0.0.1", False), ("192.168.1.1", False), ("example.com", False),
])
def test_is_local(host, local):
    assert dm._is_local(host) is local


def test_network_guard_blocks_everything_but_this_machine(monkeypatch):
    saved = (socket.socket.connect, socket.socket.connect_ex, socket.socket.sendto, socket.getaddrinfo)
    monkeypatch.setattr(dm, "ENABLED", True)
    try:
        dm.install_network_guard()
        with pytest.raises(socket.gaierror):
            socket.getaddrinfo("example.com", 443)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with pytest.raises(PermissionError):
            s.connect(("1.1.1.1", 443))
        s.close()
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        with pytest.raises(PermissionError):
            u.sendto(b"x", ("8.8.8.8", 53))
        u.close()
        assert socket.getaddrinfo("127.0.0.1", 80)
    finally:
        socket.socket.connect, socket.socket.connect_ex, socket.socket.sendto, socket.getaddrinfo = saved
        if hasattr(socket, "_pq_demo_guard"):
            del socket._pq_demo_guard


def _seed_db(path):
    with closing(sqlite3.connect(path)) as c:
        c.executescript("""
            CREATE TABLE organizations (id TEXT PRIMARY KEY, name TEXT);
            CREATE TABLE morrow_users (id TEXT PRIMARY KEY, org_id TEXT, email TEXT);
            CREATE TABLE morrow_refresh_tokens (token_hash TEXT, user_id TEXT);
            CREATE TABLE assets (asset_key TEXT, organization_id TEXT, notes TEXT);
            CREATE TABLE audit_logs (id INTEGER PRIMARY KEY, organization_id TEXT, actor_id TEXT);
            CREATE TABLE platform_analytics_snapshots (id INTEGER PRIMARY KEY, payload TEXT);
            CREATE TRIGGER trg_audit_logs_no_delete BEFORE DELETE ON audit_logs
            BEGIN SELECT RAISE(ABORT, 'audit_logs is immutable'); END;
        """)
        for org, user in ((ORG, "u1"), (OTHER, "u2")):
            c.execute("INSERT INTO organizations VALUES (?, 'Example Financial Group')", (org,))
            c.execute("INSERT INTO morrow_users VALUES (?, ?, ?)", (user, org, f"{org}@demo.invalid"))
            c.execute("INSERT INTO morrow_refresh_tokens VALUES ('h', ?)", (user,))
            c.execute("INSERT INTO assets VALUES ('www.example.com:443', ?, 'visitor note')", (org,))
            c.execute("INSERT INTO audit_logs (organization_id, actor_id) VALUES (?, ?)", (org, user))
            c.execute("INSERT INTO platform_analytics_snapshots (payload) VALUES (?)", (f'{{"orgs":["{org}"]}}',))
        c.commit()


def _traces(path, org):
    n = 0
    with closing(sqlite3.connect(path)) as c:
        for (t,) in c.execute("SELECT name FROM sqlite_master WHERE type='table'"):
            for col in [r[1] for r in c.execute(f'PRAGMA table_info("{t}")')]:
                n += c.execute(f'SELECT COUNT(*) FROM "{t}" WHERE CAST("{col}" AS TEXT) LIKE ?', (f"%{org}%",)).fetchone()[0]
    return n


def test_purge_leaves_no_trace_and_keeps_audit_log_immutable(tmp_path, monkeypatch):
    db = tmp_path / "demo.db"
    monkeypatch.setenv("MORROW_SCANNER_DB", str(db))
    monkeypatch.setenv("MORROW_DATA_DIR", str(tmp_path))
    _seed_db(db)

    assert dm.purge_workspace(ORG) > 0
    assert _traces(db, ORG) == 0
    assert _traces(db, OTHER) > 0
    with closing(sqlite3.connect(db)) as c:
        assert c.execute("SELECT COUNT(*) FROM morrow_refresh_tokens WHERE user_id='u1'").fetchone()[0] == 0
        assert c.execute("SELECT COUNT(*) FROM morrow_refresh_tokens WHERE user_id='u2'").fetchone()[0] == 1
        with pytest.raises(sqlite3.IntegrityError):
            c.execute("DELETE FROM audit_logs")


def test_purge_refuses_non_demo_ids():
    with pytest.raises(ValueError):
        dm.purge_workspace("00000000-0000-0000-0000-000000000001")
