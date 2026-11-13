"""When could traffic recorded today be decrypted? One answer for every view in Morrow.

The public grade (services/public_grade.py), the console's scan results (policy.py) and the
instrument pages all ask the same question about a connection: if someone records it now, from
which year could they read it back? The years and their source live here, once, so a scan result
and a public grade can never quote different dates for the same handshake.

The dates are not invented here. The Global Risk Institute's Quantum Threat Timeline Report 2025
(Mosca and Piani, evolutionQ; published 9 March 2026; 26 experts surveyed in 2025) puts the chance
of a quantum computer able to break RSA-2048 within 24 hours at 28-49% within 10 years ("quite
possible") and 51-70% ("likely") within 15 years. Counted from the 2025 survey that is 2035 to
2040. Update both numbers, the basis text and public_grade.RUBRIC_VERSION together when a new
edition is published.

What the answer depends on is the key exchange, nothing else. A recorded session is decrypted by
recovering its session key, and that key comes from the key exchange. The certificate signature
only has to resist forgery while the connection is live, so it does not change the date.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

DECRYPT_YEAR_LOW = 2035
DECRYPT_YEAR_HIGH = 2040
EXPOSURE_SOURCE_URL = "https://globalriskinstitute.org/publication/quantum-threat-timeline-report-2025b/"
EXPOSURE_SOURCE_LABEL = "Global Risk Institute, Quantum Threat Timeline Report 2025"
EXPOSURE_BASIS = (
    "Global Risk Institute, Quantum Threat Timeline Report 2025 (Mosca and Piani, published March "
    "2026): experts put the chance of a quantum computer that can break RSA-2048 in 24 hours at "
    "28-49% within 10 years and 51-70% within 15 years of the 2025 survey, i.e. about 2035 to 2040. "
    "Traffic recorded today with classical key exchange could be decrypted from then on."
)
PQ_BASIS = (
    "The key exchange includes ML-KEM (NIST FIPS 203), so a recording of today's traffic cannot be "
    "decrypted later by breaking the key exchange with a quantum computer."
)
PQ_SOURCE_URL = "https://csrc.nist.gov/pubs/fips/203/final"
NO_TLS_BASIS = "No TLS was negotiated, so there is no encryption to break."
UNOBSERVED_NOTE = (
    "The key exchange could not be seen on this connection, so it is treated as classical: the date "
    "is the at-risk one until a scan shows otherwise."
)
STATIC_RSA_NOTE = (
    "RSA key transport is accepted, so anyone who obtains the server's private key, today or later, "
    "can read every recorded session that used it, with or without a quantum computer."
)

#: Key-exchange families that include a post-quantum KEM (scanner.py's key_exchange_family values).
PQ_FAMILIES = ("pq_hybrid", "pq_pure")


def exposure(tls: bool, post_quantum: bool) -> Dict[str, Any]:
    """The ``exposure`` block of a public grade. Its shape is part of the public API."""
    if not tls:
        return {"recorded_traffic_at_risk": True, "decrypt_year_low": None, "decrypt_year_high": None,
                "basis": NO_TLS_BASIS, "source_url": EXPOSURE_SOURCE_URL}
    if not post_quantum:
        return {"recorded_traffic_at_risk": True, "decrypt_year_low": DECRYPT_YEAR_LOW,
                "decrypt_year_high": DECRYPT_YEAR_HIGH, "basis": EXPOSURE_BASIS,
                "source_url": EXPOSURE_SOURCE_URL}
    return {"recorded_traffic_at_risk": False, "decrypt_year_low": None, "decrypt_year_high": None,
            "basis": PQ_BASIS, "source_url": PQ_SOURCE_URL}


def for_scan_result(facts: Dict[str, Any]) -> Dict[str, Any]:
    """The decrypt window for one console scan result (an endpoint the organisation scanned).

    ``status`` is one of:
      * ``protected``   the observed key exchange includes ML-KEM; no quantum date applies;
      * ``at_risk``     classical key exchange (or not observed): readable from ``readable_from``;
      * ``unknown``     the scan did not observe this endpoint's cryptography at all.
    """
    facts = facts or {}
    scanned = str(facts.get("scan_status") or "ok") == "ok" and not facts.get("error")
    observed = bool(facts.get("key_exchange_observed"))
    family = str(facts.get("key_exchange_family") or "")
    group = str(facts.get("key_exchange") or "") or None
    notes = []
    if not scanned:
        return {"status": "unknown", "readable_from": None, "readable_by": None, "key_exchange": group,
                "basis": "The scan did not reach this endpoint's TLS, so there is nothing to date.",
                "source_url": None, "notes": notes}
    accepted = [str(c).upper() for c in (facts.get("tls12_accepted_ciphers") or [])]
    if any(c.startswith(("AES", "DES-CBC3", "RC4", "CAMELLIA", "SEED", "IDEA")) and "DHE" not in c for c in accepted):
        notes.append(STATIC_RSA_NOTE)
    if observed and family in PQ_FAMILIES:
        return {"status": "protected", "readable_from": None, "readable_by": None, "key_exchange": group,
                "basis": PQ_BASIS, "source_url": PQ_SOURCE_URL, "notes": notes}
    if not observed:
        notes.insert(0, UNOBSERVED_NOTE)
    return {"status": "at_risk", "readable_from": DECRYPT_YEAR_LOW, "readable_by": DECRYPT_YEAR_HIGH,
            "key_exchange": group, "basis": EXPOSURE_BASIS, "source_url": EXPOSURE_SOURCE_URL,
            "notes": notes}


def secret_outlives(lifetime_years: Optional[int], now: Optional[datetime] = None) -> Optional[Dict[str, Any]]:
    """Does a secret sent today need to stay secret past the earliest decrypt year?

    ``lifetime_years`` is how long the data must stay confidential (a medical record: decades; a
    session cookie: hours). Returns None when the lifetime is unknown.
    """
    if lifetime_years is None:
        return None
    try:
        years = max(0, int(lifetime_years))
    except (TypeError, ValueError):
        return None
    year = (now or datetime.now(timezone.utc)).year
    until = year + years
    return {"secret_until": until, "earliest_decrypt": DECRYPT_YEAR_LOW,
            "exposed": until >= DECRYPT_YEAR_LOW, "years_exposed": max(0, until - DECRYPT_YEAR_LOW)}


#: The range the harvest clock lets a person pick the quantum year from. ``low`` and ``likely`` are
#: the survey's two answers above (10 and 15 years from the 2025 survey). The survey names no
#: single upper date, so ``high`` is Morrow's own outer bound for the dial, and is labelled so.
CRQC_ESTIMATE = {
    "low": DECRYPT_YEAR_LOW,
    "likely": DECRYPT_YEAR_HIGH,
    "high": DECRYPT_YEAR_HIGH + 5,
    "low_label": "quite possible: experts give it 28-49% by then",
    "likely_label": "likely: experts give it 51-70% by then",
    "high_label": "a cautious outer bound Morrow uses for the dial, not a survey answer",
    "is_estimate": True,
}
#: How long a secret can be asked to last, in years. Past this the answer no longer changes.
SHELF_YEARS_MAX = 75
MIGRATION_YEARS_MAX = 20


def _clamp_int(value: Any, low: int, high: int, default: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, number))


def harvest(tls: bool, post_quantum: bool, shelf_years: Any, crqc_year: Any = None,
            migration_years: Any = 0, now: Optional[datetime] = None) -> Dict[str, Any]:
    """The harvest clock: will what is sent today stay secret as long as it has to?

    Mosca's inequality: data that must stay secret for ``x`` years (``shelf_years``), protected by a
    key exchange it takes ``y`` years to replace (``migration_years``), is exposed when
    ``x + y > z``, ``z`` being the years until a cryptographically relevant quantum computer
    (``crqc_year``, an estimate inside :data:`CRQC_ESTIMATE`).

    What a recording of today's traffic can be read with depends only on the key exchange the scan
    saw: a hybrid or pure ML-KEM exchange is not harvestable, a classical one is readable from
    ``crqc_year``, and no TLS at all is readable now. Pure: no I/O; the clock is only read for the
    current year.

    The browser computes the same thing as the dials move (static/instrument.js, harvestClock);
    this function is the reference the tests pin.
    """
    year = (now or datetime.now(timezone.utc)).year
    x = _clamp_int(shelf_years, 0, SHELF_YEARS_MAX, 0)
    y = _clamp_int(migration_years, 0, MIGRATION_YEARS_MAX, 0)
    z_year = _clamp_int(crqc_year, year, int(CRQC_ESTIMATE["high"]) + 20, int(CRQC_ESTIMATE["low"]))
    secret_until = year + x
    out: Dict[str, Any] = {
        "year": year, "shelf_years": x, "migration_years": y, "crqc_year": z_year,
        "secret_until": secret_until, "crqc_estimate": dict(CRQC_ESTIMATE),
        "mosca": {"x": x, "y": y, "z": z_year - year},
    }
    if not tls:
        out.update({"harvestable": True, "readable_from": year, "years_short": x, "margin_years": 0,
                    "exposed": x > 0, "basis": NO_TLS_BASIS})
        out["mosca"]["exposed"] = x > 0
        return out
    if post_quantum:
        out.update({"harvestable": False, "readable_from": None, "years_short": 0, "margin_years": None,
                    "exposed": False, "basis": PQ_BASIS})
        # Nothing is left to migrate for this handshake, so y does not apply to it.
        out["mosca"].update({"y": 0, "exposed": False})
        return out
    # With y years to finish switching, the last exposed secret is sent y years from now.
    last_until = secret_until + y
    out.update({
        "harvestable": True, "readable_from": z_year, "years_short": max(0, secret_until - z_year),
        "margin_years": max(0, z_year - secret_until), "exposed": secret_until > z_year,
        "basis": EXPOSURE_BASIS,
        "last_exposed_secret_until": last_until, "years_short_after_migration": max(0, last_until - z_year),
    })
    out["mosca"]["exposed"] = x + y > z_year - year
    return out


def basis() -> Dict[str, Any]:
    """Everything a page needs to quote the dates, with their source. Served at /api/public/basis."""
    return {
        "decrypt_year_low": DECRYPT_YEAR_LOW,
        "decrypt_year_high": DECRYPT_YEAR_HIGH,
        "source_label": EXPOSURE_SOURCE_LABEL,
        "source_url": EXPOSURE_SOURCE_URL,
        "basis": EXPOSURE_BASIS,
        "pq_basis": PQ_BASIS,
        "pq_source_url": PQ_SOURCE_URL,
        "crqc_estimate": dict(CRQC_ESTIMATE),
    }
