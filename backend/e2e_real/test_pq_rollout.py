"""Gradual post-quantum rollout with health gates read from a real Prometheus (HTTPS) scraping a real
Envoy: the classic listener (:10443) is the baseline, the X25519MLKEM768-only listener (:11443) the
post-quantum side. A stage passes on healthy traffic; switching the traffic generator to clients
that only offer X25519 (and to requests that return 503) makes the gate fail and roll back."""
from __future__ import annotations

import time

from .conftest import set_traffic_mode, wait_for

PROMETHEUS = "https://prometheus.e2e.morrow.test:9090"
PQ, CLASSIC = "0.0.0.0_11443", "0.0.0.0_10443"
WINDOW = "2m"  # wide enough to survive a missed scrape on a slow runner


def _http_error_rate(prefix):
    return (f'sum(rate(envoy_http_downstream_rq_xx{{envoy_response_code_class="5",envoy_http_conn_manager_prefix="{prefix}"}}[{WINDOW}]))'
            f' / sum(rate(envoy_http_downstream_rq_total{{envoy_http_conn_manager_prefix="{prefix}"}}[{WINDOW}]))')


METRICS = {
    "prometheus_url": PROMETHEUS,
    "pq_label": PQ,
    "baseline_label": CLASSIC,
    "queries": {
        # $variant form: the listener address label differs between the two sides.
        "handshake_failure_rate": (
            f'sum(rate(envoy_listener_ssl_connection_error{{envoy_listener_address="$variant"}}[{WINDOW}]))'
            f' / sum(rate(envoy_listener_downstream_cx_total{{envoy_listener_address="$variant"}}[{WINDOW}]))'),
        # Explicit form: the HTTP connection manager prefixes are named differently.
        "http_error_rate": {"pq": _http_error_rate("pq_hybrid"), "baseline": _http_error_rate("classic")},
    },
}


def _rollout(api, name):
    return api.post("/pq-rollouts", json={
        "name": name, "platform": "envoy", "soak_minutes": 1, "mode": "manual", "dry_run": True,
        "spec": {"service": "edge", "host": "envoy.e2e.morrow.test", "classic_upstream": "envoy:10443",
                 "pq_upstream": "envoy:11443", "pq_groups": ["X25519MLKEM768"]},
        "metrics": METRICS,
    })


def _gate(result, gate):
    return next(g for g in result["gates"] if g["gate"] == gate)


def _start_stage(api, rid):
    proposed = api.post(f"/pq-rollouts/{rid}/advance")
    assert proposed["proposed"]["outcome"] == "dry_run"
    assert "X25519MLKEM768" in proposed["proposed"]["config"]
    return api.post(f"/pq-rollouts/{rid}/mark-applied")


def test_gate_passes_on_healthy_traffic_then_fails_and_rolls_back(api):
    set_traffic_mode("normal")
    rollout = _rollout(api, "e2e edge rollout")
    rid = rollout["id"]
    approved = api.post(f"/pq-rollouts/{rid}/approve")
    assert approved["status"] == "approved"
    assert "error" not in approved["baseline"], approved["baseline"]

    soaking = _start_stage(api, rid)
    live_at = time.monotonic()
    assert soaking["stage_state"] == "soaking" and soaking["current_weight"] == 1

    # While soaking, a passing gate keeps the stage soaking ("inconclusive" only until Prometheus
    # has two samples of both sides in the window).
    def gate_passes():
        tick = api.post(f"/pq-rollouts/{rid}/evaluate", role="operator")["tick"]
        assert tick["result"] in ("soaking", "awaiting_approval"), tick
        return tick if tick["gate"]["result"] == "pass" else None

    gate = wait_for(gate_passes, 180, interval=5, what="a passing gate")["gate"]
    hs = _gate(gate, "handshake_failure_rate")
    assert hs["pq"] == 0 and hs["baseline"] == 0, hs
    assert _gate(gate, "http_error_rate")["pq"] == 0

    # soak_minutes=1: once a minute has passed since the stage went live, a passing gate completes it.
    def stage_passed():
        current = api.get(f"/pq-rollouts/{rid}")
        if current["stage_state"] == "awaiting_approval":  # the gate check above already completed it
            return current
        tick = api.post(f"/pq-rollouts/{rid}/evaluate", role="operator")
        return tick if tick["tick"]["result"] == "awaiting_approval" else None

    time.sleep(max(0.0, 62 - (time.monotonic() - live_at)))
    passed = wait_for(stage_passed, 180, interval=5, what="the 1% stage to pass its soak")
    assert passed["stage_state"] == "awaiting_approval"

    # Stage 2 (10%): old clients appear and the post-quantum side starts returning 503s.
    _start_stage(api, rid)
    set_traffic_mode("fail")
    try:
        def failed():
            tick = api.post(f"/pq-rollouts/{rid}/evaluate", role="operator")
            return tick if tick["tick"]["result"] == "rolled_back" else None

        rolled = wait_for(failed, 240, interval=5, what="the gate to fail")
    finally:
        set_traffic_mode("normal")
    assert rolled["status"] == "rolled_back"
    assert rolled["rollback"]["outcome"] == "dry_run"
    assert rolled["rollback"]["weight"] == 0
    # Whichever gate crosses its threshold first trips the rollback (on the 2026-11-07 run the 503s
    # did, before enough failed handshakes were scraped); each failing gate is named with its values.
    failing = [g for g in rolled["tick"]["gate"]["gates"] if g["result"] == "fail"]
    assert failing, rolled["tick"]
    reasons = {"handshake_failure_rate": "old clients failed the new handshake",
               "http_error_rate": "HTTP errors rose behind the post-quantum listener"}
    for g in failing:
        assert g["pq"] > g["baseline"] + g["max_delta"], g
        assert reasons[g["gate"]] in rolled["rollback_reason"]
        assert g["label"] in rolled["rollback_metric"]

    summary = api.get("/pq-rollouts/summary")
    assert summary["rolled_back"] >= 1


def test_unreachable_prometheus_is_inconclusive_not_a_pass(api):
    bad = dict(METRICS, prometheus_url="https://prometheus.e2e.morrow.test:9999")
    rollout = api.post("/pq-rollouts", json={
        "name": "e2e unreachable", "platform": "envoy", "soak_minutes": 1, "dry_run": True,
        "spec": {"service": "edge2", "host": "envoy.e2e.morrow.test", "classic_upstream": "envoy:10443",
                 "pq_upstream": "envoy:11443"},
        "metrics": bad,
    })
    rid = rollout["id"]
    api.post(f"/pq-rollouts/{rid}/approve")
    _start_stage(api, rid)
    tick = api.post(f"/pq-rollouts/{rid}/evaluate", role="operator")["tick"]
    assert tick["result"] == "soaking" and tick["gate"]["result"] == "inconclusive", tick
    assert all("could not be reached" in g["detail"] for g in tick["gate"]["gates"]), tick
