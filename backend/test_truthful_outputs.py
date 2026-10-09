"""Modelled output is labelled, and fabricated intelligence is not served.

Covers the launch-readiness rules for user-facing figures:
  * every endpoint that returns modelled or reference data carries model_basis
  * all Q-Day years come from one model (services/q_intel.py)
  * attribution returns network facts only, never actor labels
  * the vendor scorecard serves no platform-authored scores for named companies
  * adversary harvest estimates, peer percentiles and "network" member counts are gone
  * Demo Lab seeding works only in local development
  * generated artifacts carry configured values, never placeholder domains or OIDs
  * an empty workspace gets "not enough data yet", never a score computed from zero
  * no service reintroduces a hardcoded sector average, percentile or quartile
"""
import os
import re

os.environ.setdefault("PQC_AUTH_JWT_SECRET", "test-secret-for-unit-tests-only-x9z7q8r1m2n3")

import pytest
from fastapi.testclient import TestClient

import app as fastapi_app

HEADERS = {"x-user-role": "admin", "x-user-id": "truth-admin", "x-org-id": "truth-test-org"}

_AS_OF = re.compile(r"^\d{4}-\d{2}$")


def _assert_model_basis(body, kinds=("model", "reference", "seed")):
    basis = body.get("model_basis")
    assert isinstance(basis, dict), f"model_basis missing in {sorted(body)}"
    assert set(basis) == {"kind", "summary", "assumptions", "sources", "as_of"}
    assert basis["kind"] in kinds
    assert isinstance(basis["summary"], str) and basis["summary"].strip()
    assert isinstance(basis["assumptions"], list)
    assert isinstance(basis["sources"], list)
    assert _AS_OF.match(basis["as_of"]), basis["as_of"]
    return basis


@pytest.fixture(scope="module")
def client():
    with TestClient(fastapi_app.app) as c:
        yield c


# ── model_basis on labelled endpoints ────────────────────────────────────────

@pytest.mark.parametrize("method,path,payload,kinds", [
    ("GET", "/qday/countdown", None, ("model",)),
    ("GET", "/q-intel/model", None, ("model",)),
    ("GET", "/q-intel/feed", None, ("seed",)),
    ("GET", "/qday-forecast", None, ("model",)),
    ("GET", "/qday-forecast/milestones", None, ("seed",)),
    ("GET", "/qday-forecast/threat-actors", None, ("reference",)),
    ("GET", "/hndl/dashboard", None, ("model",)),
    ("GET", "/hndl/timeline", None, ("model",)),
    ("GET", "/actuarial/individual", None, ("model",)),
    ("POST", "/roi-calculator", {}, ("model",)),
    ("GET", "/quantum-sim/graph", None, ("model",)),
    ("GET", "/contagion/graph", None, ("model",)),
    ("GET", "/dark-matter/map", None, ("model",)),
    ("GET", "/peer-benchmark", None, ("reference",)),
    ("GET", "/qtisn/dashboard", None, ("model",)),
    ("GET", "/vendor-scorecard", None, ("reference",)),
    ("GET", "/vendor-scorecard/summary", None, ("reference",)),
    ("POST", "/vendor-scorecard/compare", {"vendor_ids": ["aws", "gcp"]}, ("reference",)),
    ("GET", "/providers/capabilities", None, ("reference",)),
    ("POST", "/attribution/analyze", {"trigger_ip": "10.1.2.3"}, ("reference",)),
])
def test_labelled_endpoints_carry_model_basis(client, method, path, payload, kinds):
    res = client.request(method, path, headers=HEADERS, json=payload)
    assert res.status_code == 200, res.text[:300]
    _assert_model_basis(res.json(), kinds)


# ── Q-Day: one source of truth ────────────────────────────────────────────────

def test_qday_years_share_one_source(client):
    from services.hndl import default_q_day_year
    from services.q_intel import q_day_reference
    from services.red_team_sim import _reference_years

    ref = q_day_reference("rsa2048")
    assert ref["accelerated_year"] <= ref["expected_year"] <= ref["conservative_year"]

    countdown = client.get("/qday/countdown", headers=HEADERS).json()
    assert countdown["estimates"]["median"] == ref["expected_year"]

    dashboard = client.get("/hndl/dashboard", headers=HEADERS).json()
    assert dashboard["q_day_year_source"] == "q_intel_model"
    assert dashboard["q_day_year"] == default_q_day_year()["year"] == max(2027, min(ref["expected_year"], 2040))

    forecast = client.get("/qday-forecast", headers=HEADERS).json()
    assert forecast["key_dates"]["estimated_crqc_year"] == ref["expected_year"]

    assert _reference_years()["expected"] == float(ref["expected_year"])


def test_qday_forecast_has_no_unsourced_consensus_or_actor_intel(client):
    res = client.get("/qday-forecast", headers=HEADERS)
    body = res.json()
    assert body["threat_actors"] == []
    for phrase in ("Gartner", "McKinsey", "PLA planning", "leaked", "Analyst consensus"):
        assert phrase not in res.text
    actors = client.get("/qday-forecast/threat-actors", headers=HEADERS).json()
    assert actors["threat_actors"] == []


def test_q_intel_seed_rows_are_marked_and_unverified_figures_removed(client):
    body = client.get("/q-intel/feed?limit=100", headers=HEADERS).json()
    seeds = [m for m in body["milestones"] if m["is_seed"]]
    assert seeds, "seed milestones should be present"
    assert all(m["kind"] == "seed" for m in seeds)
    heron_r2 = [m for m in seeds if m["system"] == "Heron r2"]
    assert heron_r2 and heron_r2[0]["logical_qubits_eq"] == 0
    majorana = [m for m in seeds if m["system"] == "Majorana 1"]
    assert majorana and majorana[0]["error_rate"] is None


# ── Removed: attribution, adversary harvest, peers, network counts, vendor scores ──

def test_attribution_returns_no_actor_labels(client):
    res = client.post("/attribution/analyze", headers=HEADERS, json={
        "trigger_ip": "10.1.2.3", "trigger_ua": "masscan/1.3", "canary_tier": "beta",
        "trigger_time_iso": "2026-09-01T03:00:00Z",
    })
    assert res.status_code == 200
    body = res.json()
    assert body["attribution_provided"] is False
    for key in ("actor", "actor_display", "confidence", "confidence_level"):
        assert key not in body
    for label in ("MSS", "SVR", "FSB", "APT", "Lazarus", "MOIS", "RGB", "nation-state"):
        assert label not in res.text

    import services.attribution as attribution
    assert not hasattr(attribution, "_ASN_ATTRIBUTION")
    assert not hasattr(attribution, "_APT_IP_RANGES")


def test_vendor_scorecard_returns_no_named_vendors(client):
    listing = client.get("/vendor-scorecard", headers=HEADERS)
    assert listing.status_code == 200
    assert listing.json()["vendors"] == []
    compare = client.post("/vendor-scorecard/compare", headers=HEADERS, json={"vendor_ids": ["aws", "cloudflare"]})
    assert compare.status_code == 200
    assert compare.json()["vendors"] == []
    summary = client.get("/vendor-scorecard/summary", headers=HEADERS).json()
    assert summary["total_vendors"] == 0 and summary["top_vendors"] == []
    assert client.get("/vendor-scorecard/aws", headers=HEADERS).status_code == 404
    for name in ("Amazon Web Services", "Google Cloud", "Microsoft Azure", "Cloudflare", "Okta", "DigiCert"):
        assert name not in listing.text
        assert name not in summary.__repr__()


def test_dark_matter_map_has_no_adversary_estimates(client):
    res = client.get("/dark-matter/map", headers=HEADERS)
    assert res.status_code == 200
    body = res.json()
    assert "adversary_models" not in body
    assert "likely_harvested" not in body["meta"]
    for rec in body["key_records"]:
        for key in ("adversary_scores", "p_any_adversary", "highest_threat_adversary", "harvest_years"):
            assert key not in rec

    from services.dark_matter import build_dark_matter_map
    mapped = build_dark_matter_map([[{"host": "api.example.cn", "port": 443, "cert_key_type": "RSA", "cert_key_bits": 2048},
                                     {"host": "shop.example.com", "port": 443}]])
    cn, com = mapped["key_records"]
    assert cn["country"] == "CN" and cn["country_source"] == "tld"
    assert com["country"] is None and com["lat"] is None and com["risk_score"] is None
    assert "adversary" not in repr(mapped)


def test_peer_benchmark_is_unavailable_without_peer_data(client):
    body = client.get("/peer-benchmark", headers=HEADERS).json()
    assert body["available"] is False and body["reason"]
    for key in ("percentile", "quartile_label", "peers_ahead_of_you", "sector_stats", "cross_sector_comparison"):
        assert key not in body


def test_qtisn_is_labelled_local(client):
    body = client.get("/qtisn/dashboard", headers=HEADERS).json()
    assert body["network_scope"] == "local"
    assert "member_organizations" not in body
    assert "omega_triggered_globally" not in body
    assert "In production" not in str(body)
    history = client.get("/qtisn/history", headers=HEADERS).json()
    assert history["network_scope"] == "local"


# ── Demo Lab: local development only ─────────────────────────────────────────

@pytest.mark.parametrize("environment,production", [("staging", False), ("production", True)])
def test_demo_seed_blocked_outside_local_even_with_allow_flag(monkeypatch, environment, production):
    monkeypatch.setattr(fastapi_app, "PQC_ENVIRONMENT", environment)
    monkeypatch.setattr(fastapi_app, "PRODUCTION_ENVIRONMENT", production)
    monkeypatch.setattr(fastapi_app, "_ALLOW_DEMO_IN_PRODUCTION", True)
    monkeypatch.setenv("PQC_ALLOW_UNSAFE_PRODUCTION_STARTUP", "1")
    with TestClient(fastapi_app.app) as c:
        res = c.post("/demo/lab/seed", headers={"x-user-role": "admin", "x-user-id": "a"}, json={})
        cfg = c.get("/auth/config").json()
    assert res.status_code == 403
    assert "local development" in res.json()["detail"]
    assert cfg["demo_lab_available"] is False
    assert cfg["environment"] == environment


def test_auth_config_reports_local_demo_lab(monkeypatch):
    monkeypatch.setattr(fastapi_app, "PQC_ENVIRONMENT", "local")
    monkeypatch.setattr(fastapi_app, "PRODUCTION_ENVIRONMENT", False)
    with TestClient(fastapi_app.app) as c:
        cfg = c.get("/auth/config").json()
    assert cfg["environment"] == "local"
    assert cfg["demo_lab_available"] is True


def test_demo_lab_records_are_marked_and_fictional():
    facts = fastapi_app._demo_lab_result(fastapi_app.DemoLabSeedRequest().target)
    assert facts["source"] == "demo-lab" and facts["demo_lab"] is True
    assert facts["host"].endswith(".invalid")
    assert "Cloudflare" not in repr(facts)


# ── Generated artifacts: configuration, not placeholders ─────────────────────

def test_hybrid_cert_omits_private_extension_without_configured_oid(monkeypatch):
    from services.public_config import private_enterprise_oid
    monkeypatch.delenv("PQC_PRIVATE_ENTERPRISE_OID", raising=False)
    assert private_enterprise_oid() == ""
    monkeypatch.setenv("PQC_PRIVATE_ENTERPRISE_OID", "1.3.6.1.4.1.99999.1")
    assert private_enterprise_oid() == "", "the old demo arc must be rejected"
    monkeypatch.setenv("PQC_PRIVATE_ENTERPRISE_OID", "1.3.6.1.4.1.61234.7")
    assert private_enterprise_oid() == "1.3.6.1.4.1.61234.7"

    import inspect
    import services.hybrid_cert as hybrid_cert
    assert "99999" not in inspect.getsource(hybrid_cert)


def test_credentials_and_links_come_from_configuration(monkeypatch):
    monkeypatch.delenv("PQC_DID_WEB_DOMAIN", raising=False)
    monkeypatch.delenv("PQC_PUBLIC_BASE_URL", raising=False)
    monkeypatch.delenv("PQC_STATUS_PAGE_URL", raising=False)
    monkeypatch.setattr(fastapi_app, "_airlock_sign", lambda payload: {"value": "sig"})

    bare = fastapi_app._w3c_credential("org-1", "PQCReadinessCredential", {"id": "x"})
    assert "issuer" not in bare
    assert "pqc-scanner.local" not in repr(bare)
    assert bare["proof"]["cryptosuite"] == "hmac-sha256-airlock"

    monkeypatch.setenv("PQC_PUBLIC_BASE_URL", "https://app.acme.test")
    configured = fastapi_app._w3c_credential("org-1", "PQCReadinessCredential", {"id": "x"})
    assert configured["issuer"] == "did:web:app.acme.test:org:org-1"
    monkeypatch.setenv("PQC_DID_WEB_DOMAIN", "trust.acme.test")
    assert fastapi_app._w3c_credential("org-1", "T", {})["issuer"] == "did:web:trust.acme.test:org:org-1"

    from services.cicd_gate import generate_gate_yaml
    from services.sast_scanner import _to_sarif
    assert "https://app.acme.test" in generate_gate_yaml()
    assert _to_sarif([])["runs"][0]["tool"]["driver"]["informationUri"] == "https://app.acme.test"
    monkeypatch.delenv("PQC_PUBLIC_BASE_URL")
    assert "example.com" not in generate_gate_yaml()
    assert "informationUri" not in _to_sarif([])["runs"][0]["tool"]["driver"]


def test_incident_template_does_not_assert_customer_data_was_safe(monkeypatch):
    from services.emergency_response import _build_comms
    monkeypatch.delenv("PQC_STATUS_PAGE_URL", raising=False)
    message = _build_comms("qday", 3, {"name": "Q-Day"})[-1]["message"]
    assert "No customer data has been compromised" not in message
    assert "[Confirm before sending:" in message
    assert "example.com" not in message
    monkeypatch.setenv("PQC_STATUS_PAGE_URL", "https://status.acme.test")
    assert "https://status.acme.test" in _build_comms("qday", 3, {"name": "Q-Day"})[-1]["message"]


def test_codegen_uses_marked_placeholder_when_host_missing(client):
    res = client.post("/pqc-codegen/generate", headers=HEADERS, json={"target": "nginx"})
    assert res.status_code == 200
    body = res.json()
    assert body["host"] == "<your-host>"
    assert "example.com" not in body["code"]


# ── Empty workspace: "not enough data yet", never a score computed from zero ──
#
# A brand-new organization id has no assets, scans, findings or remediations,
# which is exactly what a fresh install looks like. Every score, classification,
# projection and verdict below must report that it cannot be measured, and say
# what the customer has to do to get a real number.

EMPTY_HEADERS = {"x-user-role": "admin", "x-user-id": "truth-admin", "x-org-id": "truth-empty-workspace-0001"}

#: endpoint -> (path to the block that must be unavailable, keys that must be null there)
EMPTY_STATE_CASES = [
    ("/crypto-agility", (), ["cryptoflex_score", "classification", "weakest_dimension",
                             "top_recommendation", "emergency_response_estimate"]),
    ("/board-risk", (), ["score", "maturity"]),
    ("/board-risk/regulatory", (), []),
    ("/board-risk/leaderboard", (), []),
    ("/migration-velocity", (), ["recommendation"]),
    ("/compliance-mapping", (), ["overall_compliance_score", "pqc_grade"]),
    ("/actuarial/individual", (), ["risk_tier", "estimated_total_exposure_usd",
                                   "avg_annual_breach_probability", "loaded_premium_annual_usd"]),
    ("/executive-dashboard", ("executive_signal",), ["status"]),
    ("/trust-passport", ("payload", "passport"), ["score"]),
    ("/fips-pqc/report", ("migration_timeline",), ["estimated_sprint_weeks", "target_score",
                                                   "current_score", "on_track"]),
]


def _dig(body, path):
    for key in path:
        body = body[key]
    return body


@pytest.mark.parametrize("path,block,null_keys", EMPTY_STATE_CASES)
def test_empty_workspace_reports_not_enough_data(client, path, block, null_keys):
    res = client.get(path, headers=EMPTY_HEADERS)
    assert res.status_code == 200, res.text[:300]
    body = _dig(res.json(), block)

    assert body["available"] is False, f"{path} still claims a result on an empty workspace"
    assert isinstance(body["reason"], str) and body["reason"].strip(), f"{path} gives no reason"
    minimum = body["minimum_data"]
    assert isinstance(minimum, dict) and minimum, f"{path} does not say what it needs"
    assert minimum["how_to_get_it"].strip(), f"{path} does not say how to get the data"
    # The reason has to name the remedy, not just state a failure.
    assert "scan" in (body["reason"] + minimum["how_to_get_it"]).lower()

    for key in null_keys:
        assert body[key] is None, f"{path}.{key} is {body[key]!r}, expected null on an empty workspace"


def test_empty_workspace_board_and_agility_components_are_all_unmeasured(client):
    board = client.get("/board-risk", headers=EMPTY_HEADERS).json()
    assert [c["score"] for c in board["components"]] == [None] * len(board["components"])
    assert [c["weighted_points"] for c in board["components"]] == [None] * len(board["components"])
    assert board["top_risks"] == []
    # Weights stay visible so the console can still explain the model.
    assert all(isinstance(c["weight"], int) and c["weight"] > 0 for c in board["components"])

    agility = client.get("/crypto-agility", headers=EMPTY_HEADERS).json()
    assert all(d["score"] is None and d["available"] is False for d in agility["dimensions"].values())
    assert agility["measured_dimensions"] == []
    assert sorted(agility["unmeasured_dimensions"]) == sorted(agility["dimensions"])

    regulatory = client.get("/board-risk/regulatory", headers=EMPTY_HEADERS).json()
    for framework in regulatory["frameworks"]:
        assert framework["alignment_score"] is None
        assert framework["status"] == "not_assessed"


def test_empty_workspace_velocity_claims_no_completion(client):
    res = client.get("/migration-velocity", headers=EMPTY_HEADERS)
    body = res.json()
    assert body["projection"]["on_track_for_2030"] is None
    assert body["projection"]["completion_date"] is None
    assert body["velocity"]["trend"] is None
    assert body["snapshot"]["progress_pct"] is None
    assert "Migration complete" not in res.text


def test_empty_workspace_compliance_report_withholds_readiness_score(client):
    summary = client.get("/org/compliance-report?format=json", headers=EMPTY_HEADERS).json()["summary"]
    assert summary["compliance_readiness_score"] is None
    assert summary["compliance_readiness_available"] is False
    assert summary["compliance_readiness_reason"].strip()


# ── No unsourced comparison figures anywhere in these responses ──────────────

#: Keys that only ever exist to compare the customer against organizations the
#: platform holds no data about.
_FABRICATED_COMPARISON_KEYS = (
    "sector_avg", "sector_average", "industry_avg", "industry_average", "industry_average_pct",
    "sector_percentile", "peer_percentile", "percentile", "top_quartile", "bottom_quartile",
    "quartile_label", "peers_ahead_of_you", "sector_stats", "cross_sector_comparison",
    "peer_comparison", "industry_baseline", "peer_avg",
)

_COMPARISON_ENDPOINTS = [
    "/crypto-agility", "/board-risk", "/board-risk/regulatory", "/board-risk/leaderboard",
    "/migration-velocity", "/compliance-mapping", "/peer-benchmark", "/executive-dashboard",
    "/actuarial/individual", "/fips-pqc/report", "/org/compliance-report?format=json",
]


def _keys_anywhere(node):
    if isinstance(node, dict):
        for key, value in node.items():
            yield key
            yield from _keys_anywhere(value)
    elif isinstance(node, list):
        for value in node:
            yield from _keys_anywhere(value)


@pytest.mark.parametrize("path", _COMPARISON_ENDPOINTS)
def test_no_unsourced_comparison_figures_are_served(client, path):
    body = client.get(path, headers=EMPTY_HEADERS).json()
    found = sorted({k for k in _keys_anywhere(body) if k in _FABRICATED_COMPARISON_KEYS})
    assert not found, f"{path} serves invented comparison figures: {found}"


def test_crypto_agility_states_that_no_peer_comparison_exists(client):
    body = client.get("/crypto-agility", headers=EMPTY_HEADERS).json()
    comparison = body["industry_comparison"]
    assert comparison["available"] is False
    assert "no other organization" in comparison["reason"].lower()
    assert set(comparison) == {"available", "reason", "your_score"}
    _assert_model_basis(body, ("model",))


def test_agent_peer_benchmark_serves_no_invented_industry_average():
    from services.ai_agent import _exec_peer_benchmark
    result = _exec_peer_benchmark("truth-empty-workspace-0001")
    assert result["available"] is False
    for key in _FABRICATED_COMPARISON_KEYS:
        assert key not in result
    assert "1,200" not in repr(result)


def test_agent_and_api_share_one_agility_model():
    """The agent used to answer with its own invented formula (pct * 0.6 + 20)."""
    from services.ai_agent import _exec_crypto_agility
    result = _exec_crypto_agility("truth-empty-workspace-0001")
    assert result["available"] is False and result["cryptoflex_score"] is None
    assert "grade" not in result


# ── A workspace WITH data still gets a real score ────────────────────────────

def test_agility_and_board_still_score_when_evidence_exists():
    from services.board_risk import build_quantum_risk_index
    from services.crypto_agility import build_crypto_agility_report

    agility = build_crypto_agility_report(
        total_assets=10, scanned_assets=10, scan_frequency_days=7.0,
        algorithms_in_use=["RSA-2048"] * 6 + ["ML-KEM-768"] * 4,
        quantum_vulnerable_count=6, critical_vuln_count=2,
        avg_remediation_days=12.0, open_remediations=3, resolved_remediations=9,
        has_cicd_gate=True, canary_token_count=6, playbook_count=4,
        alert_rule_count=4, has_security_intent=True,
    )
    assert agility["available"] is True
    assert 0 < agility["cryptoflex_score"] <= 100
    assert agility["classification"]
    assert agility["measured_dimensions"] == sorted(agility["dimensions"])
    # Weighted contributions still sum to the composite.
    total = sum(d["weighted_contribution"] for d in agility["dimensions"].values())
    assert abs(total - agility["cryptoflex_score"]) <= 0.6

    qri = build_quantum_risk_index(
        compliance={"summary": {"assets_total": 10, "open_assets": 4, "remediations_total": 5,
                                "validated_passed_total": 3, "verified_closed_total": 2, "drifted_total": 1}},
        portfolio={"summary": {"assets_total": 10, "assets_with_quantum_data": 8,
                               "blocked_assets": 1, "actionable_migration_paths": 4,
                               "average_crypto_agility_score": 60.0}},
        metrics={"roi": {}, "drift_analytics": {"drift_events_total": 5}},
        policy={"version": "v1"},
    )
    assert qri["available"] is True
    assert 0 < qri["score"] <= 100
    assert qri["maturity"] in ("unmanaged", "early", "developing", "progressing", "managed")


def test_velocity_still_projects_when_assets_exist():
    from services.migration_velocity import build_velocity_report
    body = build_velocity_report(
        scans=[{"host": "a.example.test", "port": 443, "algorithm": "RSA-2048",
                "scan_time": "2026-09-01T00:00:00Z"}],
        remediations=[],
    )
    assert body["available"] is True
    assert body["snapshot"]["total_assets"] == 1
    assert body["snapshot"]["quantum_vulnerable_assets"] == 1
    assert body["recommendation"]
    # One vulnerable asset is not a finished migration.
    assert "Migration complete" not in body["recommendation"]


# ── Guard: the cleaned services must not grow new invented constants ─────────

#: Services this sweep cleaned. A hardcoded sector/industry/percentile/quartile
#: figure must not reappear in any of them.
_CLEANED_SERVICES = (
    "services/crypto_agility.py",
    "services/board_risk.py",
    "services/migration_velocity.py",
    "services/compliance_mapping.py",
    "services/peer_benchmark.py",
    "services/dark_matter.py",
    "services/vendor_scorecard.py",
    "services/attribution.py",
)

#: An assignment of a bare number to a comparison-flavoured name, e.g.
#: ``sector_avg = 38`` or ``"top_quartile": 65``.
_INVENTED_CONSTANT = re.compile(
    r"""(?ix)
    ["']?                                              # optional dict-key quote
    \w*(?:sector|industry|peer|percentile|quartile|benchmark|baseline)\w*
    ["']?
    \s*[:=]\s*
    -?\d+(?:\.\d+)?                                    # a bare literal number
    """
)


@pytest.mark.parametrize("relative_path", _CLEANED_SERVICES)
def test_no_hardcoded_sector_or_percentile_constants_reappear(relative_path):
    import pathlib
    source = (pathlib.Path(__file__).parent / relative_path).read_text(encoding="utf-8")
    # Strip the module docstring: prose may legitimately name these ideas to
    # explain why the platform does not publish them.
    body = source.split('"""', 2)[-1] if source.lstrip().startswith('"""') else source
    hits = [m.group(0).strip() for m in _INVENTED_CONSTANT.finditer(body)]
    assert not hits, f"{relative_path} reintroduces invented comparison constants: {hits}"


def test_cleaned_services_publish_no_percentile_or_quartile_fields():
    import pathlib
    for relative_path in _CLEANED_SERVICES:
        source = (pathlib.Path(__file__).parent / relative_path).read_text(encoding="utf-8")
        for banned in ('"sector_percentile"', '"sector_avg"', '"top_quartile"', '"bottom_quartile"',
                       '"industry_average_pct"', '"percentile"'):
            assert banned not in source, f"{relative_path} still serves {banned}"


def test_elliptic_curve_key_types_are_classified_as_quantum_vulnerable():
    """scan_results stores the bare key type ("EC"), not a curve name. Without an entry for it the
    FIPS report filed those assets as "unknown" and understated the risk."""
    from services.fips_pqc import classify_algorithm

    for key_type in ("EC", "ec", "ECC", "EC-256", "ECDSA", "P-256", "RSA"):
        result = classify_algorithm(key_type)
        assert result["status"] == "quantum_vulnerable", f"{key_type} classified {result['status']}"
        assert result["risk"] in {"critical", "high"}
    assert classify_algorithm("ML-KEM-768")["status"] == "compliant"
