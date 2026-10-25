"""Seed one public registry record into the demo database, for the promotional film.

Why a seeded record rather than a real check
--------------------------------------------
``/check`` is the only part of this platform that connects to a machine the requester may not own,
and the rule for anything recorded or published is that it makes no third-party request. Running a
live check to film the result would break that: it would open a TLS connection to somebody's host
so that a marketing video had something to show.

So the record is written straight into the demo database through the service's own
``store_result``, exactly as a completed check would write it, and the film navigates to
``/r/example.com``, which renders from stored data and touches nothing. The page and the badge in
the film are the real page and the real badge, produced by the real renderer -- only the
observation behind them was composed here instead of measured.

``example.com`` is reserved by IANA for documentation (RFC 2606), which is also why every hostname
in seed-demo-data.py sits under it. Nothing in the film names a real third party.

Usage (demo/video/run-demo-server.py does not need to be running; this writes the file directly):

    backend/.venv/Scripts/python.exe demo/video/seed-promo-record.py
"""
from __future__ import annotations

import os
import pathlib
import sys
from datetime import datetime, timedelta, timezone

ROOT = pathlib.Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
DEMO_DB = pathlib.Path(os.environ.get("MORROW_DEMO_DB") or (ROOT / "demo" / "video" / "demo.db"))

os.environ["MORROW_SCANNER_DB"] = str(DEMO_DB)      # before anything imports db
os.environ["MORROW_FEATURE_STORE_BACKEND"] = "sqlite"
os.environ["MORROW_PUBLIC_CHECK_ENABLED"] = "1"
os.environ["MORROW_PUBLIC_CHECK_IP_SALT"] = "demo-film-salt"
os.environ.setdefault("MORROW_LLM_DISABLED", "1")
sys.path.insert(0, str(BACKEND))

DOMAIN = "example.com"


def observation(when: datetime, *, key_type: str, key_bits: int, curve: str, sig: str,
                tls: str, cipher: str, kx: str, family: str) -> dict:
    """One endpoint observation, shaped as services/public_check.observe_endpoint returns it.

    build_result() turns this into the page, so the verdict, the algorithm cards, the HNDL tier and
    the deadlines are all derived by the product rather than written here. That is the point: the
    film shows what the platform concludes, not what a script typed.
    """
    return {
        "host": DOMAIN, "port": 443, "address_checked": "93.184.216.34",
        "scan_status": "ok", "error": "", "error_code": "",
        "tls_version": tls, "cipher_name": cipher, "cipher_bits": 256, "alpn": "h2",
        "certificate_verified": True, "verify_error": "",
        "key_exchange": kx, "key_exchange_family": family, "key_exchange_observed": True,
        "key_exchange_observation_method": "tls_client_hello_probe",
        "key_exchange_unobservable_reason": "", "key_exchange_hello_retry": False,
        "subject": f"CN={DOMAIN}", "issuer": "CN=Example Internal CA 3,O=Example Financial Group",
        "not_before": (when - timedelta(days=40)).isoformat().replace("+00:00", "Z"),
        "not_after": (when + timedelta(days=50)).isoformat().replace("+00:00", "Z"),
        "days_until_expiry": 50,
        "key_type": key_type, "key_bits": key_bits, "key_curve": curve, "sig_algorithm": sig,
    }


def main() -> int:
    from services import public_check as check

    check.init_tables()

    # Two observations, so the record's history has something true to show: the endpoint was
    # classical, and then it was not. A single row would make the history panel read "one
    # observation so far", which is honest but says nothing about what the register is for.
    history = [
        (datetime(2026, 7, 14, 9, 12, tzinfo=timezone.utc),
         dict(key_type="RSA", key_bits=2048, curve="", sig="sha256WithRSAEncryption",
              tls="TLSv1.2", cipher="ECDHE-RSA-AES256-GCM-SHA384", kx="secp256r1",
              family="classical")),
        (datetime(2026, 10, 2, 6, 41, tzinfo=timezone.utc),
         dict(key_type="EC", key_bits=256, curve="secp256r1", sig="ecdsa-with-SHA256",
              tls="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384", kx="X25519MLKEM768",
              family="pq_hybrid")),
    ]

    ct = {"status": "skipped", "provider": "none",
          "reason": "Certificate Transparency was not read for this record.",
          "certificate_count": None, "issuers": [], "key_history": [],
          "earliest_not_before": None, "latest_not_after": None, "entries": []}

    for when, facts in history:
        result = check.build_result(DOMAIN, observation(when, **facts), ct, checked_at=when)
        check.record_observation(DOMAIN, result)

    entry = check.registry_entry(DOMAIN)
    if entry is None:
        print("FAILED: no record was written", file=sys.stderr)
        return 1
    rows = check.registry_history(DOMAIN)
    print(f"seeded /r/{DOMAIN}: posture={entry['posture']} observations={len(rows)}")
    for row in rows:
        print(f"  {row['observed_at'][:10]}  {row['posture']:<14} {row['summary']}")
    print(f"database: {DEMO_DB}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
