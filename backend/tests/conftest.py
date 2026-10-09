"""
Shared pytest fixtures for PQC Scanner test suite.
Uses a temp-file SQLite DB so all connections share the same tables.
"""
import os
import tempfile
import pytest

# Create a shared temp DB file before importing app
_tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp_db.close()
os.environ["PQC_SCANNER_DB"] = _tmp_db.name
os.environ.setdefault("PQC_AUTH_REQUIRED", "0")
os.environ.setdefault("PQC_DEFAULT_ROLE", "admin")
os.environ.setdefault("PQC_AUTH_MODE", "headers")
os.environ.setdefault("PQC_DEFAULT_ORG_ID", "00000000-0000-0000-0000-000000000001")
os.environ.setdefault("OPENAI_API_KEY", "sk-test-placeholder")
os.environ.setdefault("PQC_MAIN_DB_BACKEND", "sqlite")

from fastapi.testclient import TestClient

TEST_ORG = "00000000-0000-0000-0000-000000000001"
AUTH_HEADERS = {
    "x-pqc-org-id": TEST_ORG,
    "x-pqc-role": "admin",
    "x-pqc-user-id": "test-user-001",
}


@pytest.fixture(scope="session")
def client():
    from app import app
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture(scope="session")
def org_id():
    return TEST_ORG


@pytest.fixture(scope="session")
def auth():
    return AUTH_HEADERS
