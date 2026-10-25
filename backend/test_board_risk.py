from services.board_risk import build_crypto_weather, build_quantum_risk_index, build_regulatory_alignment, build_team_agility_leaderboard


def _sample_inputs():
    compliance = {
        "summary": {
            "assets_total": 4,
            "open_assets": 1,
            "remediations_total": 2,
            "validated_passed_total": 1,
            "verified_closed_total": 1,
            "drifted_total": 0,
            "risk_by_asset": {"critical": 1},
        }
    }
    portfolio = {
        "summary": {
            "assets_total": 4,
            "assets_with_quantum_data": 3,
            "actionable_migration_paths": 2,
            "blocked_assets": 1,
            "average_crypto_agility_score": 70,
            "hndl_risk_counts": {"high": 1},
            "provider_counts": {"cloudflare": 2},
        }
    }
    metrics = {
        "roi": {"mttr_reduction_percent": 25.0},
        "drift_analytics": {"drift_events_total": 2, "drift_status_counts": {"clean": 2}},
    }
    policy = {"version": "test-policy"}
    return compliance, portfolio, metrics, policy


def test_quantum_risk_index_is_explainable_and_bounded():
    compliance, portfolio, metrics, policy = _sample_inputs()
    qri = build_quantum_risk_index(compliance=compliance, portfolio=portfolio, metrics=metrics, policy=policy)

    assert 0 <= qri["score"] <= 100
    assert qri["higher_is_better"] is True
    assert qri["maturity"] in {"managed", "progressing", "developing", "early", "unmanaged"}
    assert len(qri["components"]) == 6
    assert qri["executive_summary"]["policy_version"] == "test-policy"


def test_regulatory_alignment_maps_supported_frameworks():
    compliance, portfolio, metrics, policy = _sample_inputs()
    qri = build_quantum_risk_index(compliance=compliance, portfolio=portfolio, metrics=metrics, policy=policy)
    alignment = build_regulatory_alignment(qri=qri, compliance=compliance, portfolio=portfolio, metrics=metrics)

    ids = {item["id"] for item in alignment["frameworks"]}
    assert {"nist-sp-800-227", "fips-140-3", "dora"}.issubset(ids)
    assert all(0 <= item["alignment_score"] <= 100 for item in alignment["frameworks"])
    assert "not a certification" in alignment["disclaimer"]


def test_team_agility_leaderboard_ranks_engineering_teams():
    compliance = {
        "vulnerabilities": [
            {"asset_key": "api.example:443", "team": "payments", "risk_level": "critical", "findings_count": 2, "repository": "acme/payments"},
            {"asset_key": "ops.example:443", "team": "platform", "risk_level": "low", "findings_count": 1, "repository": "acme/platform"},
        ],
        "remediations": [
            {"asset_key": "api.example:443", "status": "pending", "validation": {}},
            {"asset_key": "ops.example:443", "status": "verified_closed", "validation": {"status": "passed"}},
        ],
    }
    portfolio = {
        "items": [
            {"asset_key": "api.example:443", "team": "payments", "quantum_readiness_level": "early", "crypto_agility_score": 35},
            {"asset_key": "ops.example:443", "team": "platform", "quantum_readiness_level": "managed", "crypto_agility_score": 90},
        ]
    }

    board = build_team_agility_leaderboard(compliance=compliance, portfolio=portfolio)

    assert board["summary"]["teams_total"] == 2
    assert board["teams"][0]["team"] == "platform"
    assert 0 <= board["teams"][0]["score"] <= 100
    assert board["teams"][0]["verified_closed_total"] == 1
    assert board["teams"][1]["team"] == "payments"
    assert board["teams"][1]["open_findings_total"] == 2


def test_crypto_weather_maps_signals_to_assets():
    compliance = {
        "vulnerabilities": [
            {"asset_key": "api.example:443", "team": "payments", "repository": "acme/payments"},
        ],
        "remediations": [
            {"id": 10, "asset_key": "ops.example:443", "status": "merged", "drift_status": "drifted"},
        ],
    }
    portfolio = {
        "items": [
            {
                "asset_key": "api.example:443",
                "tls_version": "TLSv1.0",
                "harvest_now_decrypt_later_risk": "critical",
                "classical_crypto_dependency": True,
                "classical_algorithm": "RSA-2048",
                "provider_guess": "unknown",
                "provider_pq_support_status": "unknown",
            }
        ]
    }

    weather = build_crypto_weather(compliance=compliance, portfolio=portfolio, policy={"version": "policy-v2"})

    assert weather["state"] == "storm"
    assert weather["summary"]["active_signals_total"] >= 4
    assert weather["summary"]["policy_version"] == "policy-v2"
    ids = {item["id"] for item in weather["signals"]}
    assert {"tls-legacy-front", "hndl-pressure-system", "classical-key-dependency", "provider-readiness-blocker", "remediation-drift-watch"}.issubset(ids)


def test_crypto_weather_accepts_policy_advisories():
    portfolio = {
        "items": [
            {
                "asset_key": "signing.example:443",
                "tls_version": "TLSv1.3",
                "cipher": "TLS_AES_256_GCM_SHA384",
                "classical_algorithm": "RSA-2048",
                "provider_guess": "cloudflare",
                "provider_pq_support_status": "available",
            }
        ]
    }
    policy = {
        "version": "weather-policy",
        "crypto_weather_advisories": [
            {
                "id": "rsa-2048-emergency-review",
                "title": "RSA-2048 emergency review",
                "severity": "high",
                "algorithm_tokens": ["rsa-2048"],
                "source": "internal-threat-intel",
                "reference_url": "https://example.invalid/advisories/rsa-2048",
            }
        ],
    }

    weather = build_crypto_weather(compliance={}, portfolio=portfolio, policy=policy)

    assert weather["state"] == "watch"
    assert weather["summary"]["policy_advisories_total"] == 1
    signal = next(item for item in weather["signals"] if item["id"] == "rsa-2048-emergency-review")
    assert signal["impacted_assets_total"] == 1
    impacted = signal["sample_impacted_assets"][0]
    assert impacted["asset_key"] == "signing.example:443"
    assert impacted["evidence"]["advisory_source"] == "internal-threat-intel"
