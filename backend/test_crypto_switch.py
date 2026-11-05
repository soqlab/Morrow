"""Crypto kill switch and gradual post-quantum rollout (services/crypto_switch, services/pq_rollout).

Pure tests cover plan building, priority, policy pre-flight, generated configurations and the health
gates. API tests run the real stack (fixture from test_invite_landing) with the code host, the
rescan and Prometheus replaced by fakes, so no request leaves the process.
"""

import json
import re
from datetime import timedelta

import pytest

from test_invite_landing import PASSWORD, api_fixture, make_org  # noqa: F401  (api_fixture registers the "api" fixture)

from services import code_hosts as ch
from services import crypto_switch as ks
from services import pq_rollout as pr

yaml = pytest.importorskip("yaml")


# ── Seeded inventory ─────────────────────────────────────────────────────────────────────────────

ASSETS = [
    {"asset_key": "pay.acme.example:443", "owner": "payments@acme.example", "environment": "production", "criticality": "critical",
     "confidentiality_lifetime": "25 years", "tags": ["internet-facing"], "metadata": {"server_type": "nginx"}},
    {"asset_key": "api.acme.example:443", "owner": "api@acme.example", "environment": "production", "criticality": "high",
     "confidentiality_lifetime": "5y", "tags": [], "metadata": {"server_type": "envoy"}},
    {"asset_key": "wiki.acme.example:443", "owner": "", "environment": "dev", "criticality": "low",
     "confidentiality_lifetime": "30 days", "tags": [], "metadata": {"server_type": "apache"}},
    {"asset_key": "svc.acme.example:8443", "owner": "platform@acme.example", "environment": "staging", "criticality": "medium",
     "confidentiality_lifetime": "2y", "tags": ["go"], "metadata": {}},
    {"asset_key": "old.acme.example:443", "owner": "legacy@acme.example", "environment": "production", "criticality": "high",
     "confidentiality_lifetime": "10y", "tags": [], "metadata": {"server_type": "haproxy"}},
]
FACTS = [
    {"asset_key": "pay.acme.example:443", "key_exchange": "X25519MLKEM768", "key_type": "RSA", "key_bits": 2048, "scan_id": "s1", "scanned_at": "2026-11-01T00:00:00Z"},
    {"asset_key": "api.acme.example:443", "key_exchange": "x25519_mlkem768", "key_type": "EC", "key_curve": "P-256", "scan_id": "s1", "scanned_at": "2026-11-01T00:00:00Z"},
    {"asset_key": "wiki.acme.example:443", "key_exchange": "X25519MLKEM768", "key_type": "RSA", "key_bits": 4096, "scan_id": "s1", "scanned_at": "2026-11-01T00:00:00Z"},
    {"asset_key": "svc.acme.example:8443", "key_exchange": "X25519MLKEM768", "key_type": "RSA", "key_bits": 2048, "scan_id": "s1", "scanned_at": "2026-11-01T00:00:00Z"},
    {"asset_key": "old.acme.example:443", "key_exchange": "X25519", "key_type": "RSA", "key_bits": 2048, "scan_id": "s1", "scanned_at": "2026-11-01T00:00:00Z"},
]


def test_plan_lists_every_affected_asset_in_priority_order_with_owner_and_change():
    plan = ks.build_plan("ML-KEM hybrid", "X25519", FACTS, ASSETS, batch_size=2)
    assert plan["preflight"]["allowed"] and plan["preflight"]["warnings"]          # classical fallback is flagged
    keys = [i["asset_key"] for i in plan["items"]]
    assert "old.acme.example:443" not in keys                                       # already classical, not affected
    assert keys[0] == "pay.acme.example:443" and keys[-1] == "wiki.acme.example:443"
    scores = [i["priority_score"] for i in plan["items"]]
    assert scores == sorted(scores, reverse=True)
    assert [i["batch"] for i in plan["items"]] == [1, 1, 2, 2]
    first = plan["items"][0]
    assert first["owner"] == "payments@acme.example" and first["priority"] == "p0" and first["server_type"] == "nginx"
    assert "ssl_ecdh_curve X25519;" in first["change_content"]
    by_key = {i["asset_key"]: i for i in plan["items"]}
    assert "ecdh_curves" in by_key["api.acme.example:443"]["change_content"]
    assert "SSLOpenSSLConfCmd Groups X25519" in by_key["wiki.acme.example:443"]["change_content"]
    assert "tls.X25519" in by_key["svc.acme.example:8443"]["change_content"]       # Go service
    assert plan["summary"]["unowned"] == 1


def test_signature_switch_rsa_2048_to_ml_dsa_uses_certificates_per_stack():
    plan = ks.build_plan("RSA-2048", "ML-DSA", FACTS, ASSETS)
    keys = {i["asset_key"] for i in plan["items"]}
    assert keys == {"pay.acme.example:443", "svc.acme.example:8443", "old.acme.example:443"}
    assert plan["fallback"]["name"] == "ML-DSA-65"
    nginx = next(i for i in plan["items"] if i["server_type"] == "nginx")
    assert "ssl_certificate /etc/ssl/morrow/" in nginx["change_content"] and "ml-dsa-65" in nginx["change_content"]
    java = ks.change_for("java", ks.resolve("RSA-2048"), ks.resolve("ML-DSA-65"), "a:443", "ksw_x")
    assert "jdk.tls.server.SignatureSchemes=mldsa65" in java["content"] and java["path"].endswith(".properties")


@pytest.mark.parametrize("broken,fallback,policy,assets,needle", [
    ("ML-KEM", "X25519", {"kill_switch_allow_classical_fallback": False}, [], "classical"),
    ("ML-KEM", "X25519", {"kill_switch_require_quantum_safe_fallback": True}, [], "quantum-safe"),
    ("RSA-2048", "RSA-1024", {}, [], "security"),
    ("RSA-4096", "RSA-2048", {"allowed_keys": ["RSA>=3072"]}, [], "3072"),
    ("ECDSA", "RSA-2048", {"banned_crypto_rules": [{"id": "ban-rsa-2048-eu", "regions": ["eu"], "algorithms": ["rsa-2048"]}]},
     [{"asset_key": "x:443", "tags": ["eu-west"]}], "ban-rsa-2048-eu"),
    ("X25519MLKEM768", "ML-DSA-65", {}, [], "like with like"),
    ("ML-KEM", "MLKEM768", {}, [], "covered by the declared break"),
    ("P-256", "P-384", {"kill_switch_min_security_bits": 256}, [], "at least 256"),
])
def test_preflight_refuses_fallbacks_weaker_than_policy(broken, fallback, policy, assets, needle):
    check = ks.preflight(broken, fallback, policy, assets)
    assert not check["allowed"]
    assert any(needle in r for r in check["refusals"]), check["refusals"]
    assert ks.build_plan(broken, fallback, FACTS, ASSETS, policy=policy)["items"] == [] or assets


def test_regional_ban_does_not_apply_outside_its_region():
    rule = {"banned_crypto_rules": [{"id": "ban-rsa-2048-eu", "regions": ["eu"], "algorithms": ["rsa-2048"]}]}
    assert ks.preflight("ECDSA", "RSA-2048", rule, [{"asset_key": "x:443", "tags": ["us-east"]}])["allowed"]


def test_default_fallback_builds_on_the_mesh_profile_emergency_algorithm():
    from services.advanced_pq_controls import build_crypto_mesh_profile

    profile = build_crypto_mesh_profile("mesh", emergency_algorithm="SecP256r1MLKEM768")
    assert ks.default_fallback("X25519", [{"profile": profile}]) == "SecP256r1MLKEM768"
    assert ks.default_fallback("SecP256r1MLKEM768", [{"profile": profile}]) == "X25519"
    assert ks.default_fallback("RSA-2048") == "ML-DSA-65"


def test_switched_needs_the_fallback_and_not_the_broken_algorithm():
    broken, fallback = ks.resolve("ML-KEM"), ks.resolve("X25519")
    assert ks.is_switched(fallback, broken, {"key_exchange": "X25519"})
    assert not ks.is_switched(fallback, broken, {"key_exchange": "X25519MLKEM768"})
    assert not ks.is_switched(fallback, broken, {"key_exchange": ""})


# ── Generated rollout configurations ─────────────────────────────────────────────────────────────

SPECS = {
    "envoy": {"service": "checkout", "host": "checkout.acme.example", "classic_upstream": "10.0.0.10:443", "pq_upstream": "10.0.0.11:8443"},
    "istio": {"service": "checkout", "host": "checkout.acme.example", "namespace": "shop"},
    "nginx": {"service": "checkout", "host": "checkout.acme.example", "classic_upstream": "10.0.0.10:443", "pq_upstream": "10.0.0.11:8443"},
    "haproxy": {"service": "checkout", "host": "checkout.acme.example", "classic_upstream": "10.0.0.10:443", "pq_upstream": "10.0.0.11:8443"},
}


@pytest.mark.parametrize("weight", [0, 1, 10, 50, 100])
def test_envoy_and_istio_configs_are_valid_yaml_with_the_stage_weights(weight):
    envoy = yaml.safe_load(pr.render_config("envoy", pr.normalize_spec("envoy", SPECS["envoy"]), weight))
    clusters = envoy["route_config"]["virtual_hosts"][0]["routes"][0]["route"]["weighted_clusters"]["clusters"]
    assert {c["name"]: c["weight"] for c in clusters} == {"checkout-classic": 100 - weight, "checkout-pq-hybrid": weight}
    tls = envoy["clusters"][0]["transport_socket"]["typed_config"]
    assert tls["@type"].endswith("UpstreamTlsContext")
    assert tls["common_tls_context"]["tls_params"]["ecdh_curves"] == ["X25519MLKEM768", "X25519"]
    docs = list(yaml.safe_load_all(pr.render_config("istio", pr.normalize_spec("istio", SPECS["istio"]), weight)))
    vs, dr = docs
    assert vs["kind"] == "VirtualService" and dr["kind"] == "DestinationRule"
    route = vs["spec"]["http"][0]["route"]
    assert [r["weight"] for r in route] == [100 - weight, weight]
    assert {r["destination"]["subset"] for r in route} == {s["name"] for s in dr["spec"]["subsets"]}
    assert vs["metadata"]["namespace"] == "shop" and dr["spec"]["host"] == "checkout.shop.svc.cluster.local"


def _nginx_structure(text):
    body = [ln.split("#", 1)[0].strip() for ln in text.splitlines()]
    body = [ln for ln in body if ln]
    depth = 0
    for ln in body:
        depth += ln.count("{") - ln.count("}")
        assert depth >= 0
        if not ln.endswith(("{", "}")):
            assert ln.endswith(";"), ln
    assert depth == 0
    block = re.search(r'split_clients "\$\{remote_addr\}" \$(\w+) \{(.*?)\}', text, re.S)
    assert block
    entries = [e.strip().rstrip(";").split() for e in block.group(2).strip().splitlines()]
    assert entries[-1][0] == "*"
    assert sum(float(e[0].rstrip("%")) for e in entries if e[0] != "*") <= 100
    assert f"proxy_pass ${block.group(1)};" in text
    return {e[0]: e[1] for e in entries}


@pytest.mark.parametrize("weight", [0, 1, 10, 50, 100])
def test_nginx_and_haproxy_configs_have_valid_structure(weight):
    split = _nginx_structure(pr.render_config("nginx", pr.normalize_spec("nginx", SPECS["nginx"]), weight))
    if weight == 0:
        assert split == {"*": "classic_checkout"}
    elif weight == 100:
        assert split == {"*": "pq_hybrid_checkout"}
    else:
        assert split == {f"{weight}%": "pq_hybrid_checkout", "*": "classic_checkout"}
    text = pr.render_config("haproxy", pr.normalize_spec("haproxy", SPECS["haproxy"]), weight)
    sections, servers = [], {}
    for ln in text.splitlines():
        if not ln.strip() or ln.lstrip().startswith("#"):
            continue
        if not ln.startswith(" "):
            sections.append(ln.split()[0])
        else:
            parts = ln.split()
            if parts[0] == "server":
                servers[parts[1]] = int(parts[parts.index("weight") + 1])
    assert sections == ["frontend", "backend"]
    assert servers == {"classic": 100 - weight, "pq_hybrid": weight}
    assert "default_backend be_checkout_tls" in text and "mode tcp" in text


def test_rollout_spec_rejects_values_that_could_inject_directives():
    with pytest.raises(pr.RolloutError):
        pr.normalize_spec("nginx", {**SPECS["nginx"], "pq_upstream": "10.0.0.1:443; include /etc/passwd"})
    with pytest.raises(pr.RolloutError):
        pr.normalize_spec("istio", {**SPECS["istio"], "service": "Bad Name"})
    with pytest.raises(pr.RolloutError):
        pr.normalize_stages([10, 1, 100])


# ── Health gates ─────────────────────────────────────────────────────────────────────────────────

METRICS = {"prometheus_url": "https://prometheus.acme.io",
           "queries": {"handshake_failure_rate": 'sum(rate(tls_handshake_failures_total{listener="$variant"}[5m]))',
                       "http_error_rate": 'sum(rate(http_requests_total{listener="$variant",code=~"5.."}[5m]))'}}


def fake_prometheus(values):
    """values: {(gate_word, side): number or None}. Answers like /api/v1/query does."""
    calls = []

    def fetch(base, query, token):
        calls.append({"base": base, "query": query, "token": token})
        gate = "handshake" if "handshake" in query else "http"
        side = "pq" if "pq-hybrid" in query else "baseline"
        value = values.get((gate, side), 0.0)
        result = [] if value is None else [{"metric": {}, "value": [1730000000, str(value)]}]
        return {"status": "success", "data": {"resultType": "vector", "result": result}}
    fetch.calls = calls
    return fetch


def test_gates_pass_fail_and_inconclusive():
    metrics = pr.normalize_metrics(METRICS)
    ok = pr.evaluate_gates(metrics, "tok", fake_prometheus({("handshake", "pq"): 0.012, ("handshake", "baseline"): 0.01}))
    assert ok["result"] == "pass"
    bad = pr.evaluate_gates(metrics, "tok", fake_prometheus({("handshake", "pq"): 0.09, ("handshake", "baseline"): 0.01}))
    assert bad["result"] == "fail"
    assert [g["result"] for g in bad["gates"]] == ["fail", "pass"]
    empty = pr.evaluate_gates(metrics, "tok", fake_prometheus({("http", "pq"): None}))
    assert empty["result"] == "inconclusive"


def test_metrics_source_must_be_public_https():
    for url in ("http://prom.acme.example", "https://user:pw@prom.acme.example", "https://localhost", "https://10.0.0.5",
                "https://prometheus.acme.io:9090"):
        with pytest.raises(pr.RolloutError):
            pr.normalize_metrics({**METRICS, "prometheus_url": url})


# ── API: real stack, fake code host / rescan / Prometheus ────────────────────────────────────────

def bearer(app, client, role="admin", org="org-acme"):
    email = f"{role}@{org}.example"
    with app._db() as db:
        app._issuer_create_user(db, email, PASSWORD, "", role, org)
    token = client.post("/auth/login", json={"email": email, "password": PASSWORD}).json()["access_token"]
    return {"Authorization": "Bearer " + token}


def seed_inventory(org="org-acme"):
    import db

    token = db.set_current_organization_id(org)
    try:
        for a in ASSETS:
            db.upsert_asset(a["asset_key"], owner=a["owner"], environment=a["environment"], criticality=a["criticality"],
                            confidentiality_lifetime=a["confidentiality_lifetime"], tags=a["tags"], metadata=a["metadata"])
        for f in FACTS:
            add_scan(org, f["asset_key"], f["key_exchange"], f["scan_id"], f["scanned_at"], key_type=f["key_type"],
                     key_bits=f.get("key_bits"))
    finally:
        db.reset_current_organization_id(token)


def add_scan(org, asset_key, key_exchange, scan_id, scanned_at, key_type="RSA", key_bits=2048):
    from contextlib import closing

    import db

    with closing(db.get_connection()) as conn:
        conn.execute(
            "INSERT INTO scan_results (organization_id, asset_key, scan_id, scanned_at, risk_level, quantum_score, findings_count, "
            "pq_relevance, tls_version, key_type, sig_algorithm, owner, team, environment, criticality, key_bits, key_curve, "
            "cipher_name, scan_status, key_exchange) VALUES (?, ?, ?, ?, 'medium', 50, 1, 'high', 'TLSv1.3', ?, 'sha256WithRSA', "
            "'', '', '', '', ?, '', 'TLS_AES_128_GCM_SHA256', 'ok', ?)",
            (org, asset_key, scan_id, scanned_at, key_type, key_bits, key_exchange))
        conn.commit()


class FakeCodeHost:
    def __init__(self):
        self.opened = []
        self.states = {}

    def open(self, org, repo, files, title, body="", base_branch="", connection_id="", branch=""):
        number = len(self.opened) + 1
        self.opened.append({"org": org, "repo": repo, "files": files, "title": title, "body": body})
        return {"url": f"https://github.com/{repo}/pull/{number}", "number": number, "branch": f"morrow/x{number}", "base": "main",
                "provider": "github", "provider_name": "GitHub", "request_name": "pull request", "repository": repo,
                "connection_id": "ch_test"}

    def state(self, org, repo, number, connection_id=""):
        return {"state": self.states.get(int(number), "open"), "merged_at": "2026-11-05T10:00:00Z" if self.states.get(int(number)) == "merged" else ""}


@pytest.fixture
def stack(api, monkeypatch):
    client, app = api
    make_org(client, "org-acme", "Acme")
    host = FakeCodeHost()
    monkeypatch.setattr(ch, "open_change_request", host.open)
    monkeypatch.setattr(ch, "change_request_state", host.state)
    rescans = []
    monkeypatch.setattr(app, "_create_scan_and_start", lambda targets, source="": rescans.append(list(targets)) or {"id": "scan-rescan-1"})
    notified = []
    import events
    monkeypatch.setattr(events, "emit_platform_event", lambda et, payload, dedupe_key="": notified.append((et, payload)) or {})
    seed_inventory()
    return {"client": client, "app": app, "host": host, "rescans": rescans, "notified": notified,
            "admin": bearer(app, client, "admin"), "operator": bearer(app, client, "operator"), "viewer": bearer(app, client, "viewer")}


def audit_actions(org="org-acme"):
    import db

    token = db.set_current_organization_id(org)
    try:
        return [r["action"] for r in db.list_audit_logs(limit=500)]
    finally:
        db.reset_current_organization_id(token)


def test_dry_run_is_the_default_and_opens_no_pull_requests(stack):
    c, admin = stack["client"], stack["admin"]
    res = c.post("/crypto-switch/incidents", headers=admin, json={"broken": "ML-KEM", "fallback": "X25519", "repository": "acme/edge"})
    assert res.status_code == 200, res.text
    inc = res.json()
    assert inc["dry_run"] is True and inc["status"] == "planned" and inc["counts"]["vulnerable"] == 4
    assert c.post(f"/crypto-switch/incidents/{inc['id']}/approve", headers=admin, json={}).status_code == 200
    run = c.post(f"/crypto-switch/incidents/{inc['id']}/execute", headers=admin, json={})
    assert run.status_code == 200, run.text
    assert {r["outcome"] for r in run.json()["batch_result"]["requests"]} == {"dry_run"}
    assert stack["host"].opened == []
    assert run.json()["counts"]["vulnerable"] == 4
    actions = audit_actions()
    assert {"crypto_switch.declared", "crypto_switch.approved", "crypto_switch.batch_dry_run"} <= set(actions)


def test_kill_switch_opens_prs_tracks_merge_and_confirms_by_rescan(stack):
    c, admin, host = stack["client"], stack["admin"], stack["host"]
    inc = c.post("/crypto-switch/incidents", headers=admin,
                 json={"broken": "ML-KEM", "fallback": "X25519", "repository": "acme/edge", "dry_run": False, "batch_size": 2}).json()
    iid = inc["id"]
    assert c.post(f"/crypto-switch/incidents/{iid}/execute", headers=admin, json={}).status_code == 409   # not approved yet
    assert c.post(f"/crypto-switch/incidents/{iid}/approve", headers=admin, json={}).status_code == 200
    first = c.post(f"/crypto-switch/incidents/{iid}/execute", headers=admin, json={}).json()
    assert first["batch_result"]["batch"] == 1 and len(host.opened) == 2
    assert host.opened[0]["title"].endswith("pay.acme.example:443")                 # highest priority first
    (path, content), = host.opened[0]["files"].items()
    assert path.startswith("morrow/crypto-switch/") and "ssl_ecdh_curve X25519;" in content
    assert first["counts"]["pr_open"] == 2 and first["status"] == "executing"

    host.states[1] = "merged"
    ref = c.post(f"/crypto-switch/incidents/{iid}/refresh", headers=stack["operator"]).json()
    assert ref["counts"]["merged"] == 1 and stack["rescans"] == [["pay.acme.example:443"]]
    # A scan from before the merge proves nothing; the newer rescan still shows the hybrid: mismatch.
    add_scan("org-acme", "pay.acme.example:443", "X25519MLKEM768", "scan-rescan-1", "2026-11-05T11:00:00Z")
    ref = c.post(f"/crypto-switch/incidents/{iid}/refresh", headers=admin).json()
    assert ref["counts"]["rescan_mismatch"] == 1
    add_scan("org-acme", "pay.acme.example:443", "X25519", "scan-rescan-2", "2026-11-05T12:00:00Z")
    ref = c.post(f"/crypto-switch/incidents/{iid}/refresh", headers=admin).json()
    assert ref["counts"]["switched"] == 1 and ref["progress"]["switched"] == 1
    item = next(i for i in ref["items"] if i["asset_key"] == "pay.acme.example:443")
    assert item["state"] == "switched" and item["verified_scan_id"] == "scan-rescan-2"
    status = c.get(f"/crypto-switch/incidents/{iid}", headers=stack["viewer"])
    assert status.status_code == 200 and status.json()["next_batch"] == 2
    assert "crypto_switch.refreshed" in audit_actions() and "crypto_switch.batch_opened" in audit_actions()


def test_kill_switch_policy_preflight_refusal_over_api(stack):
    import db

    db.set_integration_setting("org_policy_json::org-acme", json.dumps({"kill_switch_allow_classical_fallback": False}))
    res = stack["client"].post("/crypto-switch/incidents", headers=stack["admin"], json={"broken": "ML-KEM", "fallback": "X25519"})
    assert res.status_code == 400
    assert any("classical" in r for r in res.json()["detail"]["refusals"])
    assert "crypto_switch.preflight_refused" in audit_actions()


def test_kill_switch_steps_need_an_admin(stack):
    c, op, viewer = stack["client"], stack["operator"], stack["viewer"]
    assert c.post("/crypto-switch/incidents", headers=op, json={"broken": "ML-KEM", "fallback": "X25519"}).status_code == 403
    inc = c.post("/crypto-switch/incidents", headers=stack["admin"], json={"broken": "ML-KEM", "fallback": "X25519"}).json()
    for path in ("approve", "execute", "go-live", "cancel"):
        assert c.post(f"/crypto-switch/incidents/{inc['id']}/{path}", headers=op, json={}).status_code == 403, path
    assert c.post(f"/crypto-switch/incidents/{inc['id']}/refresh", headers=viewer).status_code == 403
    assert c.post("/crypto-switch/preflight", headers=op, json={"broken": "RSA-2048"}).json()["fallback"]["name"] == "ML-DSA-65"


def test_go_live_requires_a_fresh_approval(stack):
    c, admin = stack["client"], stack["admin"]
    inc = c.post("/crypto-switch/incidents", headers=admin, json={"broken": "ML-KEM", "fallback": "X25519", "repository": "acme/edge"}).json()
    c.post(f"/crypto-switch/incidents/{inc['id']}/approve", headers=admin, json={})
    live = c.post(f"/crypto-switch/incidents/{inc['id']}/go-live", headers=admin).json()
    assert live["dry_run"] is False and live["status"] == "planned"
    assert c.post(f"/crypto-switch/incidents/{inc['id']}/execute", headers=admin, json={}).status_code == 409
    assert stack["host"].opened == []


def test_incidents_and_rollouts_are_isolated_per_organization(stack):
    c = stack["client"]
    make_org(c, "org-beta", "Beta")
    beta = bearer(stack["app"], c, "admin", "org-beta")
    inc = c.post("/crypto-switch/incidents", headers=stack["admin"], json={"broken": "ML-KEM", "fallback": "X25519"}).json()
    assert c.get(f"/crypto-switch/incidents/{inc['id']}", headers=beta).status_code == 404
    assert c.post(f"/crypto-switch/incidents/{inc['id']}/approve", headers=beta, json={}).status_code == 404
    assert c.get("/crypto-switch/incidents", headers=beta).json()["items"] == []
    # Org beta has no inventory, so its own declaration finds nothing to switch.
    assert c.post("/crypto-switch/incidents", headers=beta, json={"broken": "ML-KEM", "fallback": "X25519"}).json()["counts"]["total"] == 0
    ro = c.post("/pq-rollouts", headers=stack["admin"], json=rollout_body()).json()
    assert c.get(f"/pq-rollouts/{ro['id']}", headers=beta).status_code == 404
    assert c.get("/pq-rollouts", headers=beta).json()["items"] == []


def rollout_body(**over):
    body = {"name": "checkout hybrid TLS", "platform": "envoy", "spec": SPECS["envoy"], "metrics": METRICS,
            "metrics_token": "prom-secret-token-1", "soak_minutes": 30, "mode": "manual", "dry_run": False,
            "repository": "acme/mesh"}
    body.update(over)
    return body


def _soak_and_evaluate(org, rollout_id, minutes=31):
    import db

    token = db.set_current_organization_id(org)
    try:
        return pr.evaluate(org, rollout_id, {"actor_id": "test-scheduler", "actor_role": "operator"},
                           now=pr._now_dt() + timedelta(minutes=minutes))
    finally:
        db.reset_current_organization_id(token)


def test_rollout_advances_stage_by_stage_only_after_gates_and_soak(stack, monkeypatch):
    c, admin, host = stack["client"], stack["admin"], stack["host"]
    prom = fake_prometheus({("handshake", "pq"): 0.011, ("handshake", "baseline"): 0.01})
    monkeypatch.setattr(pr, "_prometheus_get", prom)
    res = c.post("/pq-rollouts", headers=admin, json=rollout_body())
    assert res.status_code == 200, res.text
    ro = res.json()
    assert ro["status"] == "draft" and ro["has_token"] and "prom-secret-token-1" not in res.text
    rid = ro["id"]
    assert c.post(f"/pq-rollouts/{rid}/advance", headers=admin).status_code == 409             # not approved
    assert c.post(f"/pq-rollouts/{rid}/approve", headers=stack["operator"]).status_code == 403
    assert c.post(f"/pq-rollouts/{rid}/approve", headers=admin).json()["baseline"]["handshake_failure_rate"] == 0.01
    assert prom.calls[0]["token"] == "prom-secret-token-1" and prom.calls[0]["base"] == "https://prometheus.acme.io"
    stage = c.post(f"/pq-rollouts/{rid}/advance", headers=admin).json()
    assert stage["current_weight"] == 1 and stage["stage_state"] == "pending_merge" and len(host.opened) == 1
    cfg = yaml.safe_load(next(iter(host.opened[0]["files"].values())))
    assert cfg["route_config"]["virtual_hosts"][0]["routes"][0]["route"]["weighted_clusters"]["clusters"][1]["weight"] == 1
    assert c.post(f"/pq-rollouts/{rid}/evaluate", headers=stack["operator"]).json()["tick"]["result"] == "waiting"
    host.states[1] = "merged"
    assert c.post(f"/pq-rollouts/{rid}/evaluate", headers=admin).json()["stage_state"] == "soaking"
    early = c.post(f"/pq-rollouts/{rid}/evaluate", headers=admin).json()
    assert early["tick"]["result"] == "soaking" and early["current_weight"] == 1          # gates pass, soak not over
    assert c.post(f"/pq-rollouts/{rid}/advance", headers=admin).status_code == 409
    done = _soak_and_evaluate("org-acme", rid)
    assert done["tick"]["result"] == "awaiting_approval" and len(host.opened) == 1          # manual: waits for an admin
    nxt = c.post(f"/pq-rollouts/{rid}/advance", headers=admin).json()
    assert nxt["current_weight"] == 10 and len(host.opened) == 2
    assert "pq_rollout.stage_passed" in audit_actions() and "pq_rollout.stage_proposed" in audit_actions()


def test_automatic_rollout_opens_the_next_stage_pr_itself_and_completes(stack, monkeypatch):
    c, admin, host = stack["client"], stack["admin"], stack["host"]
    monkeypatch.setattr(pr, "_prometheus_get", fake_prometheus({}))
    rid = c.post("/pq-rollouts", headers=admin, json=rollout_body(mode="automatic", stages=[50, 100], platform="haproxy",
                                                                  spec=SPECS["haproxy"])).json()["id"]
    c.post(f"/pq-rollouts/{rid}/approve", headers=admin)
    c.post(f"/pq-rollouts/{rid}/advance", headers=admin)
    host.states[1] = "merged"
    c.post(f"/pq-rollouts/{rid}/evaluate", headers=admin)
    auto = _soak_and_evaluate("org-acme", rid)
    assert auto["tick"]["result"] == "advanced" and auto["current_weight"] == 100 and len(host.opened) == 2
    assert "weight 100" in next(iter(host.opened[1]["files"].values()))
    host.states[2] = "merged"
    c.post(f"/pq-rollouts/{rid}/evaluate", headers=admin)
    final = _soak_and_evaluate("org-acme", rid)
    assert final["status"] == "completed"
    assert c.get("/pq-rollouts/summary", headers=stack["viewer"]).json()["migrated"] == 1


def test_failed_gate_rolls_back_immediately_with_reason_metric_pr_and_notification(stack, monkeypatch):
    c, admin, host = stack["client"], stack["admin"], stack["host"]
    values = {("handshake", "pq"): 0.01, ("handshake", "baseline"): 0.01}
    monkeypatch.setattr(pr, "_prometheus_get", fake_prometheus(values))
    rid = c.post("/pq-rollouts", headers=admin, json=rollout_body(platform="nginx", spec=SPECS["nginx"])).json()["id"]
    c.post(f"/pq-rollouts/{rid}/approve", headers=admin)
    c.post(f"/pq-rollouts/{rid}/advance", headers=admin)
    host.states[1] = "merged"
    c.post(f"/pq-rollouts/{rid}/evaluate", headers=admin)
    values[("handshake", "pq")] = 0.2                                      # old clients start failing the hybrid handshake
    res = c.post(f"/pq-rollouts/{rid}/evaluate", headers=stack["operator"]).json()   # no soak needed to roll back
    assert res["status"] == "rolled_back" and res["tick"]["result"] == "rolled_back"
    assert res["rollback_reason"] == "old clients failed the new handshake"
    assert "TLS handshake failure rate 0.2000" in res["rollback_metric"]
    assert res["rollback_pr_url"].endswith("/pull/2")
    rollback_cfg = next(iter(host.opened[1]["files"].values()))
    assert "ROLLBACK" in rollback_cfg and _nginx_structure(rollback_cfg) == {"*": "classic_checkout"}
    assert any(et == "pq_rollout.rolled_back" and p["reason"] == res["rollback_reason"] for et, p in stack["notified"])
    assert "pq_rollout.rolled_back" in audit_actions()
    summary = c.get("/pq-rollouts/summary", headers=stack["viewer"]).json()
    assert summary["text"].startswith("0 migrated, 1 rolled back: old clients failed the new handshake")


def test_dry_run_rollout_opens_nothing_and_waits_for_the_customer_to_apply(stack, monkeypatch):
    c, admin = stack["client"], stack["admin"]
    monkeypatch.setattr(pr, "_prometheus_get", fake_prometheus({}))
    rid = c.post("/pq-rollouts", headers=admin, json=rollout_body(dry_run=True, platform="istio", spec=SPECS["istio"])).json()["id"]
    c.post(f"/pq-rollouts/{rid}/approve", headers=admin)
    stage = c.post(f"/pq-rollouts/{rid}/advance", headers=admin).json()
    assert stage["proposed"]["outcome"] == "dry_run" and stage["stage_state"] == "awaiting_apply"
    assert len(list(yaml.safe_load_all(stage["proposed"]["config"]))) == 2
    assert stack["host"].opened == []
    assert c.post(f"/pq-rollouts/{rid}/mark-applied", headers=stack["operator"]).status_code == 403
    assert c.post(f"/pq-rollouts/{rid}/mark-applied", headers=admin).json()["stage_state"] == "soaking"
    configs = c.get(f"/pq-rollouts/{rid}?configs=true", headers=stack["viewer"]).json()
    assert [x["weight"] for x in configs["configs"]] == [1, 10, 50, 100] and "rollback_config" in configs
