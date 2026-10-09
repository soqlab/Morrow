from datetime import datetime, timedelta, timezone

from services.crypto_governance import classify_certificate, build_shadow_it_report


def test_classify_certificate_expiring_soon():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    latest = {"cert_not_after": (now + timedelta(days=5)).isoformat(), "cert_issuer": "Test CA"}
    result = classify_certificate(latest, warning_days=30, now=now)
    assert result["status"] == "expiring_soon"
    assert result["severity"] == "high"
    assert result["days_remaining"] == 5
    assert result["issuer"] == "Test CA"


def test_shadow_it_flags_runtime_endpoint_without_management():
    assets = [
        {"asset_key": "managed.example:443", "owner": "platform", "repository_id": 7},
        {"asset_key": "unmanaged.example:443", "owner": "", "repository_id": 0},
    ]
    runtime_assets = [
        {"asset_key": "managed.example:443", "observed_count": 4},
        {"asset_key": "unmanaged.example:443", "observed_count": 9, "sources": ["alb"]},
        {"asset_key": "unknown.example:443", "observed_count": 3},
    ]

    def latest(key):
        return {"scan_id": "scan-1"} if key == "managed.example:443" else {}

    report = build_shadow_it_report(assets=assets, runtime_assets=runtime_assets, latest_for_asset=latest)
    keys = {item["asset_key"] for item in report["items"]}
    assert "managed.example:443" not in keys
    assert "unmanaged.example:443" in keys
    assert "unknown.example:443" in keys
    assert report["summary"]["unmanaged_assets"] == 2
    assert report["summary"]["unknown_assets"] == 1
