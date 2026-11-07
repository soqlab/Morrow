"""Migration proof from real scans of a real nginx, verified offline by scripts/verify_migration_proof.py.

Vulnerable scan (classical groups) -> remediation -> approved -> merged -> nginx switched to
X25519MLKEM768 -> rescan closes it (the in-process verify loop) -> signed proof (Ed25519 + ML-DSA-65)
-> the offline verifier accepts it against the published keys and the exported journal.

The remediation record itself is the one step that is not reached through a real service: Morrow
creates remediations from a connected GitHub repository (PR suggestion) and there is no token here,
so the test writes the row in the backend container with db.create_remediation, exactly as the
GitHub path would, and everything after it goes through the API.

Known gap, so the test is a strict xfail: the verify loop (db.auto_close_merged_remediations) closes
a remediation only when the rescan has no findings or risk low/none. Any classical certificate is a
finding of at least medium severity ("Elliptic-curve public key detected", "RSA certificate key
detected"), and no public CA issues ML-DSA certificates, so a real TLS endpoint never reaches
verified_closed and no proof can be issued for it, even after its key exchange is fixed. The real
run (2026-11-07) observed exactly that: after scan X25519MLKEM768, risk "critical" (RSA-2048 test
certificate), remediation left "merged". Closing on "the finding this remediation was opened for is
gone" is a product decision; when it is made this test starts passing and strict=True flags it.
"""
from __future__ import annotations

import json
import subprocess
import sys

import pytest

from .conftest import CLASSIC_GROUPS, HYBRID_GROUPS, REPO, container, run, set_nginx_groups

NGINX_KEY = "nginx.e2e.morrow.test:443"
VERIFIER = REPO / "scripts" / "verify_migration_proof.py"


def _seed_remediation(org: str) -> int:
    code = (
        "import json, db\n"
        f"t = db.set_current_organization_id({org!r})\n"
        f"r = db.create_remediation({NGINX_KEY!r}, 0, 'nginx/nginx.conf', "
        "'classical key exchange (X25519) on TLS endpoint', 'ssl_ecdh_curve X25519MLKEM768:X25519;', status='pending')\n"
        "print(json.dumps({'id': r['id']}))\n"
    )
    out = run(["docker", "exec", "-w", "/app", container("backend"), "python", "-c", code], timeout=600)
    return int(json.loads(out.strip().splitlines()[-1])["id"])


@pytest.mark.xfail(strict=True, reason="a real endpoint with a classical certificate never scans clean, so "
                   "the verify loop never closes its remediation (see module docstring)")
def test_migration_proof_from_real_scans_verifies_offline(api, verified_zone, tmp_path):
    set_nginx_groups(CLASSIC_GROUPS)
    api.scan(NGINX_KEY)  # the "before" scan: classical key exchange

    rid = _seed_remediation(api.org)
    api.post(f"/remediations/{rid}/approve", json={"note": "e2e"}, role="operator")
    api.post(f"/remediations/{rid}/mark-merged", json={}, role="operator")

    set_nginx_groups(HYBRID_GROUPS)
    after = api.scan(NGINX_KEY)
    result = next(r for r in after["results"] if r["host"] == "nginx.e2e.morrow.test")
    assert result["key_exchange"] == "X25519MLKEM768"
    rem = api.get(f"/remediations/{rid}")
    assert rem["status"] == "verified_closed", (rem["status"], result.get("risk"), result.get("findings"))

    proof = api.post(f"/remediations/{rid}/migration-proof", role="operator")
    doc = proof["document"]
    algs = sorted(k["alg"] for k in doc["signing_keys"])
    assert algs == ["Ed25519", "ML-DSA-65"], doc["signing_keys"]
    assert sorted(s["alg"] for s in proof["signatures"]) == ["Ed25519", "ML-DSA-65"]
    assert doc["before_scan"]["key_exchange_group"].lower() == "x25519"
    assert doc["after_scan"]["key_exchange_group"] == "X25519MLKEM768"
    keys = api.get("/.well-known/morrow-proof-keys.json")
    journal = api.get("/audit/journal/export")
    for name, doc in (("proof.json", proof), ("keys.json", keys), ("journal.json", journal)):
        (tmp_path / name).write_text(json.dumps(doc))

    ok = subprocess.run([sys.executable, str(VERIFIER), str(tmp_path / "proof.json"), "--keys", str(tmp_path / "keys.json"),
                         "--journal", str(tmp_path / "journal.json")], capture_output=True, text=True, timeout=120)
    assert ok.returncode == 0, ok.stdout + ok.stderr

    tampered = json.loads(json.dumps(proof))
    tampered["document"]["after_scan"]["key_exchange_group"] = "x25519"
    (tmp_path / "tampered.json").write_text(json.dumps(tampered))
    bad = subprocess.run([sys.executable, str(VERIFIER), str(tmp_path / "tampered.json"), "--keys", str(tmp_path / "keys.json")],
                         capture_output=True, text=True, timeout=120)
    assert bad.returncode == 1, bad.stdout + bad.stderr
