"""CBOM paths against the running backend.

* POST /v1/cbom/import with CBOMkit output: a real CBOMkit document (tests/fixtures/cbomkit, produced
  by CBOMkit on Keycloak) and, when MORROW_E2E_THEIA_IMAGE names a cbomkit-theia image, a CBOM that
  cbomkit-theia generates now from this stack's certificates.
* POST /v1/runtime/cbom/ingest: the GitHub Actions step Morrow generates, run unchanged (openssl for
  the HMAC, curl for the upload) with an mci_ ingest token and the organization's signing key.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from .conftest import STATE, run

FIXTURES = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "cbomkit"


def _import(api, data: bytes, name: str):
    return api.post("/v1/cbom/import", params={"source": "cbomkit", "filename": name}, content=data,
                    headers=api.headers("admin", {"content-type": "application/json"}))


def test_import_cbomkit_output_into_inventory(api):
    data = (FIXTURES / "keycloak-cbom.json").read_bytes()
    first = _import(api, data, "keycloak-cbom.json")
    assert first["schema_valid"] is True and first["inventory_assets"] > 0
    again = _import(api, data, "keycloak-cbom.json")
    assert again["new_inventory_assets"] == 0
    assert again["deduplicated_inventory_assets"] == first["inventory_assets"]
    inv = api.get("/v1/crypto-inventory", params={"source": "cbomkit"})
    assert inv["count"] >= first["inventory_assets"]


@pytest.mark.skipif(not os.environ.get("MORROW_E2E_THEIA_IMAGE"), reason="MORROW_E2E_THEIA_IMAGE not set")
def test_import_cbom_generated_by_cbomkit_theia(api, tmp_path):
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    for name in ("nginx.pem", "envoy.pem", "prometheus.pem"):  # certificates only, no keys
        shutil.copy(STATE / "certs" / name, scan_dir / name)
    out = run(["docker", "run", "--rm", "-v", f"{scan_dir.as_posix()}:/scan:ro",
               os.environ["MORROW_E2E_THEIA_IMAGE"], "dir", "/scan"], timeout=300)
    doc = json.loads(out[out.index("{"):])
    assert doc["bomFormat"] == "CycloneDX"
    result = _import(api, json.dumps(doc).encode(), "theia-certs.json")
    assert result["schema_valid"] is True
    assert result["assets_by_type"].get("certificate", 0) >= 3, result


def _step_script(setup: dict) -> str:
    step = setup["github_actions_step"]
    body = step.split("run: |", 1)[1]
    return "\n".join(line[4:] if line.startswith("    ") else line for line in body.splitlines()).strip() + "\n"


def test_signed_ci_ingest_with_the_generated_step(api, tmp_path):
    before = len(api.get("/v1/cbom/webhook/ingests", params={"limit": 200})["ingests"])
    token = api.post("/v1/cbom/ingest-tokens", json={"name": "e2e ci"})["secret"]
    assert token.startswith("mci_")
    key = api.post("/v1/cbom/webhook/signing-key")["secret"]
    setup = api.get("/v1/cbom/webhook/setup")
    assert setup["signing_required"] is True
    script = _step_script(setup)
    assert "secrets." not in script and token not in script and key not in script

    cbom = tmp_path / "cbom.json"
    cbom.write_bytes((FIXTURES / "kafka-cbom.json").read_bytes())
    # The setup endpoint names the server as the request saw it; aim the step at the test's base URL.
    endpoint = str(api.http.base_url).rstrip("/") + "/v1/runtime/cbom/ingest"
    assert setup["endpoint"].endswith("/v1/runtime/cbom/ingest")
    script = re.sub(r"https?://[^/']+/v1/runtime/cbom/ingest", endpoint, script)
    script_file = tmp_path / "step.sh"
    script_file.write_text(script)
    bash = shutil.which("bash") or "bash"
    env = {**os.environ, "CBOM_FILE": str(cbom), "MORROW_CBOM_INGEST_TOKEN": token, "MORROW_CBOM_SIGNING_KEY": key}
    ok = subprocess.run([bash, str(script_file)], capture_output=True, text=True, env=env, timeout=60)
    assert ok.returncode == 0, ok.stderr
    assert json.loads(ok.stdout)["summary"]["total_components"] > 0

    # Same upload with a wrong key is refused; so is an unsigned one.
    bad = subprocess.run([bash, str(script_file)], capture_output=True, text=True,
                         env={**env, "MORROW_CBOM_SIGNING_KEY": "not-the-key"}, timeout=60)
    assert bad.returncode != 0
    r = api.http.post("/v1/runtime/cbom/ingest", content=cbom.read_bytes(),
                      headers={"Authorization": f"Bearer {token}", "content-type": "application/json"})
    assert r.status_code == 401 and "signed" in r.text

    ingests = api.get("/v1/cbom/webhook/ingests", params={"limit": 200})["ingests"]
    assert len(ingests) == before + 1  # only the correctly signed upload was stored
