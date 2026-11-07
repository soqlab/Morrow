"""The in-process scan worker (no Celery broker) runs the verify loop, as the Celery task does.

Found in the real-service e2e run (docs/DEMO_RUNBOOK.md): on a single-node deployment with no
broker every scan runs in app._scan_worker, which never called auto_close_merged_remediations, so a
merged remediation stayed "merged" after a clean rescan and no migration proof could ever be issued.
"""
import uuid

import app as fastapi_app
from db import (
    create_remediation,
    get_remediation,
    mark_remediation_merged,
    reset_current_organization_id,
    save_scan_row,
    set_current_organization_id,
)


def _clean_result(host):
    return {"host": host, "port": 443, "scan_status": "ok", "tls_version": "TLSv1.3",
            "key_exchange": "X25519MLKEM768", "risk": "low", "findings": []}


def _queued_scan(org):
    scan_id = str(uuid.uuid4())
    token = set_current_organization_id(org)
    try:
        save_scan_row(scan_id=scan_id, status="queued", created_at=fastapi_app._utc_now(), progress={},
                      error_text="", results=[], summary={})
    finally:
        reset_current_organization_id(token)
    return scan_id


def test_inprocess_scan_closes_merged_remediation(monkeypatch):
    org = f"org-verify-loop-{uuid.uuid4().hex[:8]}"
    host = f"svc-{uuid.uuid4().hex[:8]}.example.com"
    token = set_current_organization_id(org)
    try:
        rem = create_remediation(asset_key_str=f"{host}:443", repo_id=0, file_path="nginx.conf",
                                 vulnerability="classical key exchange", suggested_fix="enable X25519MLKEM768",
                                 status="approved")
        mark_remediation_merged(int(rem["id"]))
    finally:
        reset_current_organization_id(token)

    monkeypatch.setattr(fastapi_app, "scan_host", lambda h, p: _clean_result(h))
    scan_id = _queued_scan(org)
    fastapi_app._scan_worker(scan_id, [f"{host}:443"], org)

    token = set_current_organization_id(org)
    try:
        row = get_remediation(int(rem["id"]))
    finally:
        reset_current_organization_id(token)
    assert row["status"] == "verified_closed"
    assert row["verification_scan_id"] == scan_id


def test_inprocess_scan_leaves_merged_remediation_open_when_still_vulnerable(monkeypatch):
    org = f"org-verify-loop-{uuid.uuid4().hex[:8]}"
    host = f"svc-{uuid.uuid4().hex[:8]}.example.com"
    token = set_current_organization_id(org)
    try:
        rem = create_remediation(asset_key_str=f"{host}:443", repo_id=0, file_path="nginx.conf",
                                 vulnerability="classical key exchange", suggested_fix="enable X25519MLKEM768",
                                 status="approved")
        mark_remediation_merged(int(rem["id"]))
    finally:
        reset_current_organization_id(token)

    vulnerable = dict(_clean_result(host), key_exchange="x25519", risk="high",
                      findings=[{"id": "QV-KEX", "title": "classical key exchange"}])
    monkeypatch.setattr(fastapi_app, "scan_host", lambda h, p: dict(vulnerable, host=h))
    fastapi_app._scan_worker(_queued_scan(org), [f"{host}:443"], org)

    token = set_current_organization_id(org)
    try:
        assert get_remediation(int(rem["id"]))["status"] == "merged"
    finally:
        reset_current_organization_id(token)
