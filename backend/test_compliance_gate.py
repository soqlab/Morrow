import tempfile
from datetime import datetime, timezone

from fastapi.testclient import TestClient

import app as fastapi_app
from db import init_db, save_scan_asset_summaries, save_scan_row, upsert_asset, upsert_repository


def seed_critical_scan(asset_key: str):
    # Through the scan pipeline's own writers, so the row lands in whichever backend the gate reads
    # (SQLite here, Postgres in the CI job that sets MORROW_MAIN_DB_BACKEND=postgres). Writing
    # straight into the SQLite file left the Postgres-backed gate with nothing to find.
    host, port = asset_key.rsplit(":", 1)
    now = datetime.now(timezone.utc)
    result = {
        "host": host, "port": int(port), "risk": "critical", "quantum_risk_score": 90.0,
        "findings": [{"id": f"f{i}"} for i in range(5)], "pq_relevance": "high",
        "tls_version": "TLSv1.2", "key_type": "RSA", "sig_algorithm": "RSA",
    }
    save_scan_row(scan_id="scan-1", status="completed", created_at=now, progress={}, error_text="",
                  results=[result], summary={})
    save_scan_asset_summaries("scan-1", now.isoformat().replace("+00:00", "Z"), [result])


def test_compliance_gate_fail(monkeypatch):
    # isolated temp DB
    tmp_db = tempfile.NamedTemporaryFile(delete=False)
    monkeypatch.setenv("MORROW_SCANNER_DB", tmp_db.name)

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
