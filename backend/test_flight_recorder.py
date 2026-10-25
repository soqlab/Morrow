import os
import tempfile

from fastapi.testclient import TestClient

import app as fastapi_app
from db import append_flight_recorder_event, init_db, list_flight_recorder_events


def test_flight_recorder_persists_and_filters_intent_events():
    tmp_db = tempfile.NamedTemporaryFile(delete=False)
    os.environ["MORROW_SCANNER_DB"] = tmp_db.name
    try:
        init_db()
        append_flight_recorder_event(
            actor_type="ci",
            actor_id="buildkite",
            actor_role="operator",
            intent="block_deploy",
            resource_type="repository",
            resource_id="acme/platform",
            policy_version="policy-v1",
            decision="blocked",
            outcome="succeeded",
            reason="banned crypto in protected path",
            evidence_refs={"scan_id": "scan-1"},
        )

        rows = list_flight_recorder_events(intent="block_deploy", resource_type="repository", resource_id="acme/platform")

        assert len(rows) == 1
        assert rows[0]["actor_type"] == "ci"
        assert rows[0]["decision"] == "blocked"
        assert rows[0]["evidence_refs"]["scan_id"] == "scan-1"
    finally:
        try:
            os.remove(tmp_db.name)
        except OSError:
            pass


def test_flight_recorder_api_records_and_lists_events():
    tmp_db = tempfile.NamedTemporaryFile(delete=False)
    os.environ["MORROW_SCANNER_DB"] = tmp_db.name
    fastapi_app.app.router.on_startup.clear()
    fastapi_app.app.router.on_shutdown.clear()
    try:
        init_db()
        with TestClient(fastapi_app.app) as client:
            create = client.post(
                "/v1/flight-recorder/events",
                headers={"x-user-id": "operator-1", "x-user-role": "operator"},
                json={
                    "actor_type": "human",
                    "intent": "approve_fix",
                    "resource_type": "remediation",
                    "resource_id": "42",
                    "decision": "allowed",
                    "outcome": "succeeded",
                    "evidence_refs": {"remediation_id": 42, "pr_url": "https://github.com/acme/repo/pull/1"},
                },
            )
            assert create.status_code == 200
            event = create.json()["event"]
            assert event["intent"] == "approve_fix"
            assert event["actor_id"] == "operator-1"

            listed = client.get(
                "/v1/org/00000000-0000-0000-0000-000000000001/flight-recorder?resource_type=remediation&resource_id=42",
                headers={"x-user-id": "viewer-1", "x-user-role": "viewer"},
            )
            assert listed.status_code == 200
            body = listed.json()
            assert body["summary"]["returned"] == 1
            assert body["items"][0]["evidence_refs"]["remediation_id"] == 42
    finally:
        try:
            os.remove(tmp_db.name)
        except OSError:
            pass
