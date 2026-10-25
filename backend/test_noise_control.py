"""Deterministic end-to-end noise-control test.

This exercises:
  - state_change: fires on first sight of a fingerprint, not every scan
  - cooldown: suppress repeats for 24h
  - escalation: re-fire inside cooldown if severity worsens

Run with (PowerShell):
  $env:MORROW_SCANNER_DB = ".\\morrow_test.db"
  python test_noise_control.py

Optional: run the webhook listener in another terminal to see delivered payloads:
  python listener.py
"""

from __future__ import annotations

import os
import uuid
from contextlib import closing
from datetime import datetime, timezone, timedelta
from pathlib import Path

import db as _db
import events as _events


def _utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def fresh_db() -> None:
    """Delete the SQLite file (if it exists) so tests are deterministic."""
    db_path = os.environ.get("MORROW_SCANNER_DB")
    if not db_path:
        # default used by db.py
        db_path = str(Path(__file__).resolve().parent / "morrow.db")

    # skip special sqlite paths
    if db_path == ":memory:" or str(db_path).startswith("file:"):
        return

    p = Path(db_path).expanduser()
    try:
        if p.exists():
            p.unlink()
    except Exception:
        pass


def make_scan(scan_id: str, created_at: datetime, findings_severity: str) -> None:
    """Insert a completed scan with a single expired-cert finding."""
    # build_events_for_scan expects per-target result dict with host/port + findings.
    results = [
        {
            "host": "example.com",
            "port": 443,
            "days_until_expiry": -1,
            "not_after": "2025-01-01T00:00:00Z",
            "verify_reason": "expired",
            "findings": [
                {"rule_id": "CERT_EXPIRED", "severity": findings_severity},
            ],
        }
    ]

    _db.save_scan_row(
        scan_id=scan_id,
        status="completed",
        created_at=_utc(created_at),
        progress={"total": 1, "done": 1},
        error_text="",
        results=results,
        summary={"targets": 1},
    )


def main() -> int:
    fresh_db()
    _db.init_db()

    # Create a webhook that points to the demo listener (optional)
    wh = _db.upsert_webhook(
        name="noise-test-webhook",
        url="http://127.0.0.1:8787",  # listener.py default
        secret="",
        events=["*"],
        enabled=True,
    )

    # Create a rule for cert.expired using state_change + 24h cooldown.
    rule = _db.upsert_event_rule(
        name="cert expired (state_change + 24h cooldown)",
        enabled=True,
        webhook_ids=[int(wh["id"])],
        event_types=["cert.expired"],
        cooldown_minutes=1440,
        fire_mode="state_change",
        min_severity="",
        rule_ids=[],
        quantum_score_min=-1,
        environments=[],
        teams=[],
        criticalities=[],
        tags=[],
    )

    base_time = datetime.now(timezone.utc)

    # Scan 1: first time expired cert appears => should fire.
    scan1 = str(uuid.uuid4())
    make_scan(scan1, base_time, findings_severity="medium")
    r1 = _events.deliver_events_for_scan(scan1)
    print("scan1 delivery:", r1)

    # Scan 2: same fingerprint next minute => should be suppressed (within cooldown, no escalation)
    scan2 = str(uuid.uuid4())
    make_scan(scan2, base_time + timedelta(minutes=1), findings_severity="medium")
    r2 = _events.deliver_events_for_scan(scan2)
    print("scan2 delivery (expected suppressed):", r2)

    # Scan 3: severity worsens to CRITICAL inside cooldown => should fire (escalation)
    scan3 = str(uuid.uuid4())
    make_scan(scan3, base_time + timedelta(minutes=2), findings_severity="critical")
    r3 = _events.deliver_events_for_scan(scan3)
    print("scan3 delivery (expected escalation fire):", r3)

    # Scan 4: simulate cooldown elapsed => should fire again
    # NOTE: deliver_events_for_scan() uses *wall clock* for cooldown checks (not the scan timestamp),
    # so we backdate the fire record in SQLite to make this test deterministic.
    with closing(_db.get_connection()) as conn:
        try:
            conn.execute(
                "UPDATE event_rule_fires SET last_fired_at=? WHERE rule_id=?",
                ((base_time - timedelta(days=2)).isoformat() + "Z", int(rule.get("id"))),
            )
            conn.commit()
        except Exception:
            pass

    scan4 = str(uuid.uuid4())
    make_scan(scan4, base_time + timedelta(days=2), findings_severity="critical")
    r4 = _events.deliver_events_for_scan(scan4)
    print("scan4 delivery (expected cooldown elapsed fire):", r4)

    print("\nIf you ran listener.py, check its console output to confirm POST bodies.")
    print("Rule id:", rule.get("id"), "Webhook id:", wh.get("id"))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
