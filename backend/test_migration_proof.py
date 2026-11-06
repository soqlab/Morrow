"""Migration proofs: signed, built from Morrow's own records, checkable offline."""
import base64
import copy
import hashlib
import importlib.util
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

import app as fastapi_app
from db import (
    auto_close_merged_remediations,
    create_remediation,
    init_db,
    mark_remediation_merged,
    reset_current_organization_id,
    save_scan_asset_summaries,
    save_scan_row,
    set_current_organization_id,
)
from services import proof_signing
from db_postgres import postgres_main_db_requested, product_database_url

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VERIFIER_PATH = os.path.join(REPO_ROOT, "scripts", "verify_migration_proof.py")
_spec = importlib.util.spec_from_file_location("verify_migration_proof", VERIFIER_PATH)
verifier = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(verifier)

ORG_A = "org-proof-alpha"
ORG_B = "org-proof-beta"


def _headers(org, role="admin"):
    return {"x-org-id": org, "x-user-role": role, "x-user-id": f"{role}@{org}"}


@pytest.fixture(scope="module")
def client():
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
    tmp.close()
    previous = os.environ.get("MORROW_SCANNER_DB")
    previous_backend = os.environ.get("MORROW_FEATURE_STORE_BACKEND")
    os.environ["MORROW_SCANNER_DB"] = tmp.name
    os.environ["MORROW_FEATURE_STORE_BACKEND"] = "sqlite"
    fastapi_app.app.router.on_startup.clear()
    fastapi_app.app.router.on_shutdown.clear()
    init_db()
    proof_signing.reset_cache_for_tests()
    with TestClient(fastapi_app.app) as c:
        yield c
    proof_signing.reset_cache_for_tests()
    for key, value in (("MORROW_SCANNER_DB", previous), ("MORROW_FEATURE_STORE_BACKEND", previous_backend)):
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    try:
        os.remove(tmp.name)
    except OSError:
        pass


def _scan(org, scan_id, host, when, vulnerable, scan_status="ok"):
    result = {
        "host": host, "port": 443, "scan_status": scan_status, "scanner_version": "morrow-tls-scanner/test",
        "tls_version": "TLSv1.3" if not vulnerable else "TLSv1.2",
        "cipher_name": "TLS_AES_256_GCM_SHA384" if not vulnerable else "ECDHE-RSA-AES128-GCM-SHA256",
        "key_exchange": "X25519MLKEM768" if not vulnerable else "x25519",
        "key_exchange_observed": True,
        "key_type": "RSA", "key_bits": 2048, "sig_algorithm": "sha256WithRSAEncryption",
        "risk": "high" if vulnerable else "low",
        "findings": [{"id": "QV-KEX", "title": "classical key exchange"}] if vulnerable else [],
        "quantum_risk_score": 82.5 if vulnerable else 5.0,
    }
    token = set_current_organization_id(org)
    try:
        save_scan_row(scan_id=scan_id, status="completed", created_at=when, progress={}, error_text="",
                      results=[result], summary={})
        save_scan_asset_summaries(scan_id, scanned_at_iso=when.isoformat().replace("+00:00", "Z"), results=[result])
        return auto_close_merged_remediations(scan_id, [result])
    finally:
        reset_current_organization_id(token)


def _closed_remediation(client, org, host, verify_status="ok"):
    """Vulnerable scan, remediation, approval, merge, clean re-scan: the whole lifecycle."""
    now = datetime.now(timezone.utc)
    tag = hashlib.sha256(f"{org}{host}{now.isoformat()}".encode()).hexdigest()[:8]
    _scan(org, f"scan-before-{tag}", host, now - timedelta(days=3), vulnerable=True)
    token = set_current_organization_id(org)
    try:
        rem = create_remediation(asset_key_str=f"{host}:443", repo_id=0, file_path="nginx.conf",
                                 vulnerability="classical key exchange (x25519) on TLS endpoint",
                                 suggested_fix="enable X25519MLKEM768", status="pending")
    finally:
        reset_current_organization_id(token)
    rid = int(rem["id"])
    r = client.post(f"/remediations/{rid}/approve", json={"note": "ok"}, headers=_headers(org, "operator"))
    assert r.status_code == 200, r.text
    token = set_current_organization_id(org)
    try:
        mark_remediation_merged(rid, merged_at_iso=(now - timedelta(days=1)).isoformat().replace("+00:00", "Z"))
    finally:
        reset_current_organization_id(token)
    stats = _scan(org, f"scan-after-{tag}", host, now - timedelta(hours=1), vulnerable=False, scan_status=verify_status)
    return rid, stats


def _issue(client, org, rid):
    r = client.post(f"/remediations/{rid}/migration-proof", headers=_headers(org))
    return r


def _keys(client):
    r = client.get("/.well-known/morrow-proof-keys.json")
    assert r.status_code == 200, r.text
    return r.json()


def _journal(client, org):
    r = client.get("/audit/journal/export", headers=_headers(org))
    assert r.status_code == 200, r.text
    return r.json()


@pytest.fixture(scope="module")
def issued(client):
    rid, stats = _closed_remediation(client, ORG_A, "pay.alpha.example")
    assert stats["closed"] == 1
    r = _issue(client, ORG_A, rid)
    assert r.status_code == 200, r.text
    return {"rid": rid, "response": r.json(), "keys": _keys(client), "journal": _journal(client, ORG_A)}


def test_valid_proof_verifies_offline(issued):
    report = verifier.verify(issued["response"], keys=issued["keys"], journal=issued["journal"])
    failed = [c for c in report.checks if not c["ok"]]
    assert failed == [] and report.exit_code == 0
    doc = issued["response"]["proof"]["document"]
    assert doc["subject"]["asset_key"] == "pay.alpha.example:443"
    assert doc["before_scan"]["key_exchange_group"] == "x25519"
    assert doc["after_scan"]["key_exchange_group"] == "X25519MLKEM768"
    assert doc["after_scan"]["scanner_version"] == "morrow-tls-scanner/test"
    assert doc["issued_at"]
    algs = {s["alg"] for s in issued["response"]["proof"]["signatures"]}
    assert "Ed25519" in algs
    if proof_signing.MLDSA_AVAILABLE:
        assert "ML-DSA-65" in algs
    actions = {e["action"] for e in doc["journal"]["entries"]}
    assert {"remediation.approve", "remediation.verified_closed"} <= actions
    events = {e["event"]: e for e in doc["timeline"]}
    assert events["approved"]["journal_entry_id"] and events["verified_closed"]["journal_entry_id"]


def test_cli_verifier_runs_standalone(issued, tmp_path):
    paths = {}
    for name in ("response", "keys", "journal"):
        paths[name] = tmp_path / f"{name}.json"
        paths[name].write_text(json.dumps(issued[name]), encoding="utf-8")
    # -I: isolated mode, so only the stdlib and installed packages are importable -- not backend/.
    run = subprocess.run([sys.executable, "-I", VERIFIER_PATH, str(paths["response"]), "--keys", str(paths["keys"]),
                          "--journal", str(paths["journal"])], capture_output=True, text=True, cwd=str(tmp_path))
    assert run.returncode == 0, run.stdout + run.stderr
    assert "VERIFIED" in run.stdout
    untrusted = subprocess.run([sys.executable, "-I", VERIFIER_PATH, str(paths["response"])],
                               capture_output=True, text=True, cwd=str(tmp_path))
    assert untrusted.returncode == 3


def _set(doc, path, value):
    cur = doc
    for part in path[:-1]:
        cur = cur[part]
    cur[path[-1]] = value


@pytest.mark.parametrize("path,value", [
    (("subject", "asset_key"), "other.example:443"),
    (("subject", "organization_id"), ORG_B),
    (("finding", "remediation_id"), 999999),
    (("finding", "vulnerability"), "nothing to see"),
    (("before_scan", "risk_level"), "low"),
    (("before_scan", "key_exchange_group"), "X25519MLKEM768"),
    (("before_scan", "scanned_at"), "2020-01-01T00:00:00.000000Z"),
    (("after_scan", "cipher"), "NULL-MD5"),
    (("after_scan", "scanner_version"), "forged/1"),
    (("after_scan", "findings_count"), 3),
    (("issued_at",), "2030-01-01T00:00:00.000000Z"),
    (("timeline", 0, "at"), "2020-01-01T00:00:00.000000Z"),
    (("journal", "entries", 0, "entry_hash"), "0" * 64),
    (("journal", "head", "id"), 1),
    (("assertions", "clean_after"), False),
])
def test_any_tampered_field_fails(issued, path, value):
    proof = copy.deepcopy(issued["response"])
    _set(proof["proof"]["document"], path, value)
    report = verifier.verify(proof, keys=issued["keys"])
    assert report.exit_code == 1
    assert any(not c["ok"] and "is valid" in c["check"] for c in report.checks)


def test_stripped_or_swapped_signatures_fail(issued):
    proof = copy.deepcopy(issued["response"])
    proof["proof"]["signatures"] = [s for s in proof["proof"]["signatures"] if s["alg"] != "Ed25519"]
    assert verifier.verify(proof, keys=issued["keys"]).exit_code == 1
    proof = copy.deepcopy(issued["response"])
    if len(proof["proof"]["signatures"]) > 1:
        proof["proof"]["signatures"] = proof["proof"]["signatures"][:1]
        assert verifier.verify(proof, keys=issued["keys"]).exit_code == 1
    proof = copy.deepcopy(issued["response"])
    sig = proof["proof"]["signatures"][0]
    raw = bytearray(base64.b64decode(sig["signature"]))
    raw[0] ^= 1
    sig["signature"] = base64.b64encode(bytes(raw)).decode()
    assert verifier.verify(proof, keys=issued["keys"]).exit_code == 1


def test_wrong_key_fails(issued):
    # An attacker re-signs a modified document with their own key and embeds that key.
    proof = copy.deepcopy(issued["response"])
    doc = proof["proof"]["document"]
    doc["after_scan"]["cipher"] = "forged"
    attacker = Ed25519PrivateKey.generate()
    pub = attacker.public_key().public_bytes_raw()
    kid = issued["response"]["proof"]["signatures"][0]["kid"]
    doc["signing_keys"] = [{"kid": kid, "key_set": "ks-x", "alg": "Ed25519", "public_key": base64.b64encode(pub).decode(),
                            "fingerprint_sha256": hashlib.sha256(pub).hexdigest()}]
    sig = attacker.sign(verifier.SIGNING_CONTEXT + verifier.canonical_bytes(doc))
    proof["proof"]["signatures"] = [{"kid": kid, "alg": "Ed25519", "signature": base64.b64encode(sig).decode()}]
    report = verifier.verify(proof, keys=issued["keys"])
    assert report.exit_code == 1  # intact under the attacker's key, but not the published one
    assert verifier.verify(proof).exit_code == 3  # without trust anchors it is never "verified"
    # A keys file that does not contain the real signer fails the genuine proof too.
    other = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    fake_keys = {"format": "morrow.proof-keys/v1", "keys": [{"kid": "morrow-ed25519-feedfacefeedface", "alg": "Ed25519",
                 "public_key": base64.b64encode(other).decode(), "valid_from": "2000-01-01T00:00:00Z", "valid_until": None}]}
    assert verifier.verify(issued["response"], keys=fake_keys).exit_code == 1
    assert verifier.verify(issued["response"], pins=["ab" * 32]).exit_code == 1
    real_fp = issued["response"]["proof"]["document"]["signing_keys"][0]["fingerprint_sha256"]
    assert verifier.verify(issued["response"], pins=[real_fp]).exit_code == 0


def test_tampered_journal_export_fails(issued):
    journal = copy.deepcopy(issued["journal"])
    cited = issued["response"]["proof"]["document"]["journal"]["entries"][0]["id"]
    for e in journal["entries"]:
        if e["id"] == cited:
            e["reason"] = "rewritten"
    report = verifier.verify(issued["response"], keys=issued["keys"], journal=journal)
    assert report.exit_code == 1
    journal = copy.deepcopy(issued["journal"])
    journal["entries"] = [e for e in journal["entries"] if e["id"] != cited]
    assert verifier.verify(issued["response"], keys=issued["keys"], journal=journal).exit_code == 1


def test_non_verified_remediation_is_refused(client):
    token = set_current_organization_id(ORG_A)
    try:
        rem = create_remediation(asset_key_str="open.alpha.example:443", repo_id=0, file_path="x",
                                 vulnerability="RSA key exchange", suggested_fix="", status="approved")
    finally:
        reset_current_organization_id(token)
    r = _issue(client, ORG_A, int(rem["id"]))
    assert r.status_code == 409 and "verified_closed" in r.json()["detail"]
    assert _issue(client, ORG_A, 987654).status_code == 404


def test_verification_scan_that_did_not_connect_is_refused(client):
    # The verify loop closes on "no findings"; a scan that failed to connect has none either.
    rid, stats = _closed_remediation(client, ORG_A, "down.alpha.example", verify_status="connect_failed")
    assert stats["closed"] == 1
    r = _issue(client, ORG_A, rid)
    assert r.status_code == 409 and "did not observe" in r.json()["detail"]


def test_viewer_cannot_issue(client, issued):
    assert client.post(f"/remediations/{issued['rid']}/migration-proof", headers=_headers(ORG_A, "viewer")).status_code == 403


def test_org_isolation(client, issued):
    assert _issue(client, ORG_B, issued["rid"]).status_code == 404
    journal_b = _journal(client, ORG_B)
    a_hashes = {e["entry_hash"] for e in issued["journal"]["entries"]}
    assert not a_hashes & {e["entry_hash"] for e in journal_b["entries"]}
    assert journal_b["organization_id"] == ORG_B
    # A proof of org A does not verify against org B's journal.
    assert verifier.verify(issued["response"], keys=issued["keys"], journal=journal_b).exit_code == 1
    rid_b, _ = _closed_remediation(client, ORG_B, "pay.beta.example")
    doc_b = _issue(client, ORG_B, rid_b).json()["proof"]["document"]
    assert doc_b["subject"]["organization_id"] == ORG_B
    assert {e["id"] for e in doc_b["journal"]["entries"]}.isdisjoint(
        {e["id"] for e in issued["response"]["proof"]["document"]["journal"]["entries"]})


def test_key_rotation_keeps_old_proofs_verifiable(client, issued):
    old_kids = {s["kid"] for s in issued["response"]["proof"]["signatures"]}
    proof_signing.rotate()
    rid, _ = _closed_remediation(client, ORG_A, "api.alpha.example")
    new = _issue(client, ORG_A, rid)
    assert new.status_code == 200, new.text
    new_kids = {s["kid"] for s in new.json()["proof"]["signatures"]}
    assert old_kids.isdisjoint(new_kids)
    keys = _keys(client)
    status = {k["kid"]: k["status"] for k in keys["keys"]}
    assert all(status[k] == "retired" for k in old_kids) and all(status[k] == "active" for k in new_kids)
    assert verifier.verify(issued["response"], keys=keys).exit_code == 0
    assert verifier.verify(new.json(), keys=keys).exit_code == 0
    # A proof claiming to be issued by the old key after it was retired is outside the key's window.
    retired = next(k for k in keys["keys"] if k["kid"] in old_kids)
    late = copy.deepcopy(keys)
    for k in late["keys"]:
        if k["kid"] in old_kids:
            k["valid_until"] = "2000-01-01T00:00:00Z"
    assert retired["valid_until"]
    assert verifier.verify(issued["response"], keys=late).exit_code == 1


def test_proofs_sign_and_verify_after_vault_key_rotation(client, issued, monkeypatch, capsys):
    from cryptography.fernet import Fernet

    spec = importlib.util.spec_from_file_location("rotate_vault_master_key",
                                                  os.path.join(REPO_ROOT, "scripts", "rotate-vault-master-key.py"))
    rotation = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rotation)
    for name in ("MORROW_MAIN_DB_BACKEND", "DATABASE_URL", "MORROW_PRODUCT_DATABASE_URL"):
        monkeypatch.delenv(name, raising=False)
    old_vault_key = os.environ["MORROW_VAULT_MASTER_KEY"]
    new_vault_key = Fernet.generate_key().decode()
    monkeypatch.setenv("MORROW_VAULT_MASTER_KEY_NEW", new_vault_key)
    assert rotation.main(["--sqlite", os.environ["MORROW_SCANNER_DB"], "--apply"]) == 0
    report = json.loads(capsys.readouterr().out)
    target = report["targets"]["proof_signing_keys"]
    assert target["present"] and target["rotated"] == target["rows"] >= 2 and not target["undecryptable"]

    monkeypatch.setenv("MORROW_VAULT_MASTER_KEY", new_vault_key)
    monkeypatch.delenv("MORROW_VAULT_MASTER_KEY_NEW")
    proof_signing.reset_cache_for_tests()  # a restarted server holds no unsealed keys
    try:
        rid, _ = _closed_remediation(client, ORG_A, "vault.alpha.example")
        fresh = _issue(client, ORG_A, rid)
        assert fresh.status_code == 200, fresh.text
        keys = _keys(client)
        assert verifier.verify(fresh.json(), keys=keys).exit_code == 0
        assert verifier.verify(issued["response"], keys=keys).exit_code == 0  # public keys untouched
        # The old vault key can no longer unseal the signing key, so it cannot sign.
        monkeypatch.setenv("MORROW_VAULT_MASTER_KEY", old_vault_key)
        proof_signing.reset_cache_for_tests()
        assert _issue(client, ORG_A, rid).status_code == 503
    finally:
        monkeypatch.setenv("MORROW_VAULT_MASTER_KEY", new_vault_key)
        proof_signing.reset_cache_for_tests()


def test_private_keys_are_sealed(client, issued):
    with sqlite3.connect(os.environ["MORROW_SCANNER_DB"]) as conn:
        rows = conn.execute("SELECT algorithm, public_key_b64, sealed_private_key FROM proof_signing_keys").fetchall()
    assert rows
    for alg, pub, sealed in rows:
        assert sealed.startswith("gAAAA")  # a Fernet token from the vault, never raw key bytes
        assert pub not in sealed


def test_journal_verification_route_detects_tampering(client, issued):
    r = client.get("/audit/journal/verify", headers=_headers(ORG_A))
    assert r.status_code == 200 and r.json()["ok"] is True and r.json()["entries_checked"] > 0
    assert client.get("/audit/journal/verify", headers=_headers(ORG_A, "viewer")).status_code == 403
    target = issued["response"]["proof"]["document"]["journal"]["entries"][0]["id"]
    on_postgres = postgres_main_db_requested()
    if on_postgres:
        # The journal is in Postgres (the Postgres CI job): edit it there, as a DBA would, by
        # switching the immutability trigger off for one statement.
        import psycopg2

        with psycopg2.connect(product_database_url()) as pg, pg.cursor() as cur:
            cur.execute("ALTER TABLE audit_logs DISABLE TRIGGER trg_audit_logs_no_update")
            cur.execute("UPDATE audit_logs SET reason='edited by a DBA' WHERE id=%s", (target,))
            cur.execute("ALTER TABLE audit_logs ENABLE TRIGGER trg_audit_logs_no_update")
    else:
        with sqlite3.connect(os.environ["MORROW_SCANNER_DB"]) as conn:
            conn.execute("DROP TRIGGER IF EXISTS trg_audit_logs_no_update")
            conn.execute("UPDATE audit_logs SET reason='edited by a DBA' WHERE id=?", (target,))
    try:
        body = client.get("/audit/journal/verify", headers=_headers(ORG_A)).json()
        assert body["ok"] is False and body["breaks"][0]["id"] == target
        # And no new proof is signed over a broken chain.
        assert _issue(client, ORG_A, issued["rid"]).status_code == 409
    finally:
        if not on_postgres:
            init_db()  # recreates the immutability trigger


def test_legacy_hs256_endpoints_still_work(client):
    r = client.post("/remediation/proof-package", json={"asset_key": "legacy.example:443", "finding": "RSA"},
                    headers=_headers(ORG_A))
    assert r.status_code == 200, r.text
    assert r.json()["signature"]["alg"] == "HS256"
