"""Migration velocity counts the status Morrow actually gives a finished fix."""
from datetime import datetime, timedelta, timezone

from services.migration_velocity import build_velocity_report


def test_verified_closures_count_towards_velocity():
    now = datetime.now(timezone.utc)
    scans = [{"host": f"h{i}.example", "port": 443, "algorithm": "RSA-2048", "risk_level": "high",
              "scan_time": now.isoformat()} for i in range(10)]
    closures = [{"status": "verified_closed", "target_host": f"h{i}.example",
                 "updated_at": (now - timedelta(days=i)).isoformat()} for i in range(8)]
    report = build_velocity_report(scans, closures)
    assert sum(w["assets_migrated"] for w in report["velocity"]["weekly_history"]) == 8
    assert report["projection"]["completion_date"]
