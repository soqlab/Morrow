import os
import tempfile
from datetime import datetime

from fastapi.testclient import TestClient

import app as fastapi_app
from db import init_db, upsert_repository, upsert_asset, get_connection


def seed_critical_scan(asset_key: str):
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO scan_results (
                asset_key, scan_id, scanned_at, risk_level, quantum_score, findings_count,
                pqc_relevance, tls_version, key_type, sig_algorithm,
                owner, team, environment, criticality
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                asset_key,
                "scan-1",
                datetime.utcnow().isoformat() + "Z",
                "critical",
                90.0,
                5,
                "high",
                "TLSv1.2",
                "RSA",
                "RSA",
                "",
                "",
                "",
                "",
            ),
        )
        conn.commit()


def test_compliance_gate_fail():
    # isolated temp DB
    tmp_db = tempfile.NamedTemporaryFile(delete=False)
    os.environ["PQC_SCANNER_DB"] = tmp_db.name

    # disable startup hooks
    fastapi_app.app.router.on_startup.clear()
    fastapi_app.app.router.on_shutdown.clear()

    init_db()

    repo = upsert_repository("acme/repo", "https://github.com/acme/repo")
    upsert_asset("www.cloudflare.com:443", repository_id=repo["id"])
    seed_critical_scan("www.cloudflare.com:443")

    with TestClient(fastapi_app.app) as client:
        r = client.get(f"/api/v1/compliance/gate?repo={repo['name']}")
        assert r.status_code == 200
        body = r.json()
        assert body["exit_code"] == 1
        assert body["status"] == "FAIL"
        assert len(body["critical_assets"]) >= 1
