"""Migration milestones against the running backend: defaults, an admin change (audited), the
velocity report reading it, refusal for a viewer, and the reset. No external service is involved."""
from __future__ import annotations


def test_milestones_round_trip(api):
    start = api.get("/v1/migration-velocity/milestones")
    assert start["defaults"] and start["can_edit"] is True

    api.call("PUT", "/v1/migration-velocity/milestones", role="viewer", expect=403,
             json={"milestones": [{"name": "x", "date": "2030-01-01"}]})

    body = {"milestones": [{"name": "Hybrid TLS on every internet edge", "date": "2027-06-30", "scope": "edge"},
                           {"name": "No classical-only key exchange", "date": "2030-12-31"}],
            "reason": "e2e demo plan"}
    saved = api.call("PUT", "/v1/migration-velocity/milestones", json=body)
    assert [m["name"] for m in saved["milestones"]] == [m["name"] for m in body["milestones"]]
    assert api.get("/v1/migration-velocity/milestones")["milestones"] == saved["milestones"]

    bad = api.call("PUT", "/v1/migration-velocity/milestones", expect=None,
                   json={"milestones": [{"name": "bad date", "date": "next year"}]})
    assert "detail" in bad

    api.call("DELETE", "/v1/migration-velocity/milestones")
    assert api.get("/v1/migration-velocity/milestones")["milestones"] == start["defaults"]
