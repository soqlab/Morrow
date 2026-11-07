"""CBOM ingest (routers/cbom_ingest.py) authentication, tenancy and signing.

The route used to take its organization from X-Org-Id, ran no role check, and verified a signature
only when one was sent. These tests run on the real JWT stack (test_invite_landing's fixture).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import pathlib

import pytest

from test_invite_landing import api_fixture, make_org  # noqa: F401  (api_fixture registers the "api" fixture)
from test_domain_verification import bearer

CBOM = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {"component": {"name": "acme/app"}},
                   "components": [{"type": "cryptographic-asset", "name": "RSA-2048"}]}).encode()
JSON = {"Content-Type": "application/json"}


def _sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


@pytest.fixture
def orgs(api):
    client, app = api
    make_org(client, "org-acme", "Acme")
    make_org(client, "org-other", "Other")
    return client, app, {
        "admin": bearer(client, app, email="admin@acme.example", org="org-acme", role="admin"),
        "operator": bearer(client, app, email="op@acme.example", org="org-acme", role="operator"),
        "viewer": bearer(client, app, email="viewer@acme.example", org="org-acme", role="viewer"),
        "other": bearer(client, app, email="admin@other.example", org="org-other", role="admin"),
    }


def _ingests(client, auth):
    res = client.get("/v1/cbom/webhook/ingests", headers=auth)
    assert res.status_code == 200, res.text
    return res.json()["ingests"]


def test_no_credentials_is_401(orgs):
    client, _, _ = orgs
    assert client.post("/v1/cbom/ingest", headers=JSON, content=CBOM).status_code == 401
    assert client.post("/v1/runtime/cbom/ingest", headers=JSON, content=CBOM).status_code == 401
    # A header naming an organization is not a credential.
    assert client.post("/v1/cbom/ingest", headers={**JSON, "X-Org-Id": "org-acme"}, content=CBOM).status_code == 401
    assert client.post("/v1/runtime/cbom/ingest", headers={**JSON, "X-Org-Id": "org-acme"}, content=CBOM).status_code == 401


def test_viewer_is_403_operator_and_admin_succeed(orgs):
    client, _, a = orgs
    assert client.post("/v1/cbom/ingest", headers={**a["viewer"], **JSON}, content=CBOM).status_code == 403
    for role in ("operator", "admin"):
        res = client.post("/v1/cbom/ingest", headers={**a[role], **JSON}, content=CBOM)
        assert res.status_code == 200, res.text
        assert res.json()["organization_id"] == "org-acme"
    assert len(_ingests(client, a["admin"])) == 2
    assert _ingests(client, a["other"]) == []


def test_x_org_id_cannot_redirect_a_write(orgs):
    client, _, a = orgs
    res = client.post("/v1/cbom/ingest", headers={**a["operator"], **JSON, "X-Org-Id": "org-other"}, content=CBOM)
    assert res.status_code == 403
    assert _ingests(client, a["other"]) == [] and _ingests(client, a["admin"]) == []


def test_ci_token_names_the_org_and_header_is_ignored(orgs):
    client, app, a = orgs
    assert client.post("/v1/cbom/ingest-tokens", headers=a["operator"], json={"name": "ci"}).status_code == 403
    made = client.post("/v1/cbom/ingest-tokens", headers=a["admin"], json={"name": "ci"})
    assert made.status_code == 200, made.text
    secret = made.json()["secret"]
    assert secret.startswith("mci_") and "secret" not in json.dumps(
        client.get("/v1/cbom/ingest-tokens", headers=a["admin"]).json())
    # Hashed at rest: the secret appears nowhere in the database.
    with app._db() as db:
        dump = "\n".join(db.iterdump())
    # The random part may itself contain "_", so take everything after "mci_<prefix>_"; splitting on
    # the last "_" could leave two characters that turn up in any dump by chance.
    assert secret not in dump and secret.split("_", 2)[2] not in dump

    res = client.post("/v1/runtime/cbom/ingest",
                      headers={**JSON, "Authorization": f"Bearer {secret}", "X-Org-Id": "org-other"}, content=CBOM)
    assert res.status_code == 200, res.text
    assert res.json()["organization_id"] == "org-acme"
    assert _ingests(client, a["other"]) == [] and len(_ingests(client, a["admin"])) == 1
    # Alternative header, then revocation takes effect immediately.
    assert client.post("/v1/runtime/cbom/ingest", headers={**JSON, "X-Morrow-Ingest-Token": secret},
                       content=CBOM).status_code == 200
    token_id = made.json()["token"]["id"]
    assert client.delete(f"/v1/cbom/ingest-tokens/{token_id}", headers=a["other"]).status_code == 404
    assert client.delete(f"/v1/cbom/ingest-tokens/{token_id}", headers=a["admin"]).status_code == 200
    assert client.post("/v1/runtime/cbom/ingest", headers={**JSON, "Authorization": f"Bearer {secret}"},
                       content=CBOM).status_code == 401
    assert client.post("/v1/runtime/cbom/ingest", headers={**JSON, "Authorization": "Bearer mci_000000000000_" + "x" * 40},
                       content=CBOM).status_code == 401
    # A user session is not accepted on the token-only CI route.
    assert client.post("/v1/runtime/cbom/ingest", headers={**a["admin"], **JSON}, content=CBOM).status_code == 401


def test_signing_key_makes_signatures_mandatory(orgs):
    client, _, a = orgs
    # Viewing setup is read-only: it neither creates nor reveals a key, and needs admin.
    assert client.get("/v1/cbom/webhook/setup", headers=a["operator"]).status_code == 403
    setup = client.get("/v1/cbom/webhook/setup", headers=a["admin"]).json()
    assert setup["signing_required"] is False and "secret" not in setup
    assert "X-Org-Id" not in setup["github_actions_step"] and "/v1/runtime/cbom/ingest" in setup["github_actions_step"]
    assert client.post("/v1/cbom/ingest", headers={**a["operator"], **JSON}, content=CBOM).status_code == 200

    assert client.post("/v1/cbom/webhook/signing-key", headers=a["operator"]).status_code == 403
    key = client.post("/v1/cbom/webhook/signing-key", headers=a["admin"]).json()["secret"]
    assert client.get("/v1/cbom/webhook/setup", headers=a["admin"]).json()["signing_required"] is True
    token = client.post("/v1/cbom/ingest-tokens", headers=a["admin"], json={"name": "ci"}).json()["secret"]
    for headers in ({**a["operator"], **JSON}, {**JSON, "Authorization": f"Bearer {token}"}):
        path = "/v1/runtime/cbom/ingest" if "mci_" in headers.get("Authorization", "") else "/v1/cbom/ingest"
        unsigned = client.post(path, headers=headers, content=CBOM)
        assert unsigned.status_code == 401 and "signed" in unsigned.text
        bad = client.post(path, headers={**headers, "X-Morrow-Signature": _sign("wrong", CBOM)}, content=CBOM)
        assert bad.status_code == 401
        tampered = client.post(path, headers={**headers, "X-Morrow-Signature": _sign(key, CBOM)}, content=CBOM + b" ")
        assert tampered.status_code == 401
        good = client.post(path, headers={**headers, "X-Morrow-Signature": _sign(key, CBOM)}, content=CBOM)
        assert good.status_code == 200, good.text
    # Another organization's key does not apply to it, and its uploads stay unsigned-OK.
    assert client.post("/v1/cbom/ingest", headers={**a["other"], **JSON}, content=CBOM).status_code == 200
    assert client.delete("/v1/cbom/webhook/signing-key", headers=a["admin"]).json()["removed"] is True
    assert client.post("/v1/cbom/ingest", headers={**a["operator"], **JSON}, content=CBOM).status_code == 200


def test_body_limits_and_shape(orgs, monkeypatch):
    client, _, a = orgs
    monkeypatch.setenv("MORROW_CBOM_INGEST_MAX_BYTES", "1024")
    big = json.dumps({"components": [{"name": "x" * 2000}]}).encode()
    assert client.post("/v1/cbom/ingest", headers={**a["operator"], **JSON}, content=big).status_code == 413
    assert client.post("/v1/cbom/ingest", headers={**a["operator"], **JSON}, content=b"[1]").status_code == 400
    assert client.post("/v1/cbom/ingest", headers={**a["operator"], **JSON}, content=b"{").status_code == 400


# ── Console: "Import SBOM" sends the multipart upload /sbom/import expects ───────

CONSOLE = pathlib.Path(__file__).resolve().parent.parent / "frontend" / "index.html"


def test_console_sbom_import_sends_multipart_file():
    html = CONSOLE.read_text(encoding="utf-8")
    start = html.index("ACTIONS.sbomImportGo")
    body = html[start: html.index("};", start)]
    assert "new FormData()" in body and 'form.append("file"' in body and "body: form" in body
    assert "sbom: doc" not in html  # the JSON body the route never accepted
    # rawFetch passes FormData through untouched, without a JSON Content-Type.
    raw = html[html.index("async function rawFetch"): html.index("function refreshAccess")]
    assert "body instanceof FormData" in raw and "headers(body !== undefined && !form)" in raw
    # The console no longer posts unsigned documents to the webhook route.
    assert 'safe("/cbom/ingest"' not in html


def test_sbom_import_route_accepts_the_console_upload(orgs):
    client, _, a = orgs
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [{"type": "cryptographic-asset", "name": "RSA-2048"}]}
    res = client.post("/sbom/import", headers=a["admin"],
                      files={"file": ("sbom.json", json.dumps(sbom).encode(), "application/json")})
    assert res.status_code == 200, res.text
    assert res.json()["crypto_component_count"] == 1
    # What the console used to send.
    assert client.post("/sbom/import", headers=a["admin"], json={"sbom": sbom, "source": "manual"}).status_code == 422
