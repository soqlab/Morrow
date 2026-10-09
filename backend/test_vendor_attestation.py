import os
import tempfile

from fastapi.testclient import TestClient

import app as fastapi_app
from db import init_db


def test_vendor_attestation_invite_and_public_submission_flow():
    tmp_db = tempfile.NamedTemporaryFile(delete=False)
    os.environ["PQC_SCANNER_DB"] = tmp_db.name
    fastapi_app.app.router.on_startup.clear()
    fastapi_app.app.router.on_shutdown.clear()
    try:
        init_db()
        with TestClient(fastapi_app.app) as client:
            created = client.post(
                "/v1/vendor-attestations/invites",
                headers={"x-user-id": "operator-1", "x-user-role": "operator"},
                json={"vendor_name": "Acme SaaS", "vendor_email": "security@acme.test", "expires_days": 14},
            )
            assert created.status_code == 200
            invite = created.json()["invite"]
            assert invite["vendor_name"] == "Acme SaaS"
            assert invite.get("token")
            assert "token_hash" not in invite

            portal = client.get(f"/api/vendor-attestation/{invite['token']}")
            assert portal.status_code == 200
            assert portal.json()["invite"]["vendor_name"] == "Acme SaaS"

            portal_html = client.get(f"/vendor-attestation/{invite['token']}")
            assert portal_html.status_code == 200
            assert "text/html" in portal_html.headers["content-type"]
            assert "Vendor self-attestation portal" in portal_html.text
            assert "Acme SaaS PQC readiness attestation" in portal_html.text

            submitted = client.post(
                f"/vendor-attestation/{invite['token']}/submit",
                json={
                    "submitted_by": "Jane Vendor",
                    "signer_title": "CISO",
                    "domains": ["api.acme.test:443"],
                    "answers": {"pqc_roadmap": True, "tls13": True},
                    "evidence_refs": {"soc2": "available-under-nda"},
                    "readiness_score": 82,
                },
            )
            assert submitted.status_code == 200
            submission = submitted.json()["submission"]
            assert submission["vendor_name"] == "Acme SaaS"
            assert submission["readiness_score"] == 82
            assert submission["domains"] == ["api.acme.test:443"]

            listed = client.get(
                "/v1/org/00000000-0000-0000-0000-000000000001/vendor-attestations",
                headers={"x-user-id": "viewer-1", "x-user-role": "viewer"},
            )
            assert listed.status_code == 200
            assert listed.json()["items"][0]["submitted_by"] == "Jane Vendor"

            invites = client.get(
                "/v1/vendor-attestations/invites",
                headers={"x-user-id": "viewer-1", "x-user-role": "viewer"},
            )
            assert invites.status_code == 200
            assert invites.json()["items"][0]["status"] == "submitted"
    finally:
        try:
            os.remove(tmp_db.name)
        except OSError:
            pass
