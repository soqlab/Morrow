"""Crypto kill switch against a real nginx (OpenSSL 3.5): declare X25519 broken, switch to
X25519MLKEM768, apply the change on the real server, and see the rescan mark it switched.

No code host is connected (GitHub needs a token), so the asset is handed over as a configuration to
apply by hand (state manual_apply). The switch is still only recorded once a newer scan of the live
endpoint observes the fallback group, which is the behaviour under test.
"""
from __future__ import annotations

from .conftest import CLASSIC_GROUPS, HYBRID_GROUPS, set_nginx_groups

NGINX_KEY = "nginx.e2e.morrow.test:443"


def _result(scan, key):
    return next(r for r in scan["results"] if f"{r['host']}:{r['port']}" == key)


def _item(status, key):
    return next(i for i in status["items"] if i["asset_key"] == key)


def test_kill_switch_marks_switched_only_after_rescan_observes_fallback(api, verified_zone):
    set_nginx_groups(CLASSIC_GROUPS)
    before = _result(api.scan(NGINX_KEY), NGINX_KEY)
    assert before["scan_status"] == "ok", before.get("error")
    assert before["key_exchange"].lower() == "x25519", before["key_exchange"]

    pre = api.post("/crypto-switch/preflight", json={"broken": "X25519", "fallback": "X25519MLKEM768"}, role="operator")
    assert pre["preflight"]["allowed"] is True
    assert NGINX_KEY in [i["asset_key"] for i in pre["items"]]

    incident = api.post("/crypto-switch/incidents", json={
        "broken": "X25519", "fallback": "X25519MLKEM768", "reason": "e2e: X25519 declared broken", "dry_run": True})
    iid = incident["id"]
    assert incident["status"] == "planned" and incident["dry_run"] is True
    assert _item(incident, NGINX_KEY)["server_type"] == "nginx"

    # Dry run: approve and execute open nothing.
    api.post(f"/crypto-switch/incidents/{iid}/approve", json={"note": "dry run"})
    dry = api.post(f"/crypto-switch/incidents/{iid}/execute", json={})
    assert {r["outcome"] for r in dry["batch_result"]["requests"]} == {"dry_run"}
    change = next(r for r in dry["batch_result"]["requests"] if r["asset_key"] == NGINX_KEY)
    assert "X25519MLKEM768" in change["content"]

    # Live: leave dry run, approve again, execute. No repository, so the config is handed over.
    api.post(f"/crypto-switch/incidents/{iid}/go-live")
    api.post(f"/crypto-switch/incidents/{iid}/approve", json={"note": "go"})
    live = api.post(f"/crypto-switch/incidents/{iid}/execute", json={})
    assert _item(live, NGINX_KEY)["state"] == "manual_apply"

    # A rescan before the change is applied must not count as switched.
    api.scan(NGINX_KEY)
    still = api.post(f"/crypto-switch/incidents/{iid}/refresh", role="operator")
    assert _item(still, NGINX_KEY)["state"] == "manual_apply"

    # Apply the change on the real server, rescan, refresh.
    set_nginx_groups(HYBRID_GROUPS)
    after = _result(api.scan(NGINX_KEY), NGINX_KEY)
    assert after["key_exchange"] == "X25519MLKEM768", after["key_exchange"]
    done = api.post(f"/crypto-switch/incidents/{iid}/refresh", role="operator")
    item = _item(done, NGINX_KEY)
    assert item["state"] == "switched", item
    assert item["verified_scan_id"]

    journal = api.get("/audit/journal/verify")
    assert journal.get("ok", journal.get("valid")) is True, journal
