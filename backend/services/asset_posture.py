"""Per-asset current posture: what the newest scan of each asset said, one row per asset.

`asset_scan_latest` (both dialects) holds, for every asset, the newest `scan_results` row (the same
row latest_scan_facts_for_org used to find with a NOT EXISTS / DISTINCT ON over the whole history)
plus the few fields of the full scan result that only `scans.results_json` carries: the
certificate's expiry, issuer and subject, and the key-map facts. The certificate lifecycle,
shadow-IT and key-map reports read those columns instead of parsing the newest scans' JSON, and
/search matches a trigram index on `search_text`.

The row is written by save_scan_asset_summaries, in the same transaction as the scan_results row,
and only replaces an older one: "newer" is (scanned_at, scan_results.id), the order every reader of
scan_results uses. A database written before the table existed is backfilled once
(db.backfill_asset_scan_latest / db_postgres.pg_backfill_asset_scan_latest).

Everything here is a pure function of one scan result, so the write path and the backfill cannot
disagree.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from services.crypto_governance import _parse_datetime, certificate_expiry_value
from services.dark_matter import _infer_country, _risk_score

#: The columns save_scan_asset_summaries writes to scan_results, in the order readers get them.
FACT_COLUMNS = (
    "asset_key", "scan_id", "scanned_at", "risk_level", "quantum_score", "findings_count",
    "pq_relevance", "tls_version", "key_type", "sig_algorithm",
    "owner", "team", "environment", "criticality",
    "key_bits", "key_curve", "cipher_name", "scan_status", "key_exchange",
)

#: Taken from the full scan result (not stored in scan_results).
EXTRA_COLUMNS = (
    "host", "port", "cert_expires_raw", "cert_expires_at", "cert_issuer", "cert_subject",
    "map_included", "map_key_type", "map_key_bits", "map_tls_version", "map_country",
    "map_risk_score", "map_risk_basis",
)

#: The scan_results columns /search matches a term against (db._SCAN_FACT_SEARCH_SQL). A term must
#: fall inside one of them, so they are joined with a separator no search term can contain.
SEARCH_COLUMNS = ("asset_key", "key_type", "sig_algorithm", "tls_version", "risk_level", "owner", "team",
                  "environment")
SEARCH_SEPARATOR = "\x1f"


def normalized_expiry(raw: str) -> Optional[str]:
    """The expiry as fixed-width UTC text ("YYYY-MM-DDTHH:MM:SS.ffffffZ") so SQL can compare it, or
    None when classify_certificate would call it unknown."""
    dt = _parse_datetime(raw)
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def expiry_threshold(now: datetime, days: float = 0) -> str:
    """`now + days` in the format of normalized_expiry, for SQL comparisons against it."""
    from datetime import timedelta

    return (now.astimezone(timezone.utc) + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def result_extras(result: Dict[str, Any]) -> Dict[str, Any]:
    """The EXTRA_COLUMNS of one full scan result (see services.crypto_governance.classify_certificate
    and services.dark_matter.build_dark_matter_map, whose reads these reproduce)."""
    raw_expiry = certificate_expiry_value(result)
    host = str(result.get("host") or "")
    try:
        port = int(result.get("port") or 0) or None
    except (TypeError, ValueError):
        port = None
    key_type = str(result.get("cert_key_type") or result.get("key_type") or "")
    try:
        key_bits = int(result.get("cert_key_bits") or result.get("key_bits") or 0) or None
    except (TypeError, ValueError):
        key_bits = None
    risk, basis = _risk_score(key_type, key_bits)
    return {
        "host": host,
        "port": port,
        "cert_expires_raw": raw_expiry,
        "cert_expires_at": normalized_expiry(raw_expiry),
        "cert_issuer": str(result.get("cert_issuer") or result.get("issuer") or "").strip(),
        "cert_subject": str(result.get("cert_subject") or result.get("subject") or "").strip(),
        # The key map leaves out results that carry an error.
        "map_included": 0 if result.get("error") else 1,
        "map_key_type": key_type,
        "map_key_bits": key_bits,
        "map_tls_version": str(result.get("tls_version") or ""),
        "map_country": _infer_country(host),
        "map_risk_score": round(risk, 3) if risk is not None else None,
        "map_risk_basis": basis,
    }


def search_text(facts: Dict[str, Any]) -> str:
    """Lower-cased SEARCH_COLUMNS of a scan_results row; risk_level reads "unknown" when blank."""
    parts = []
    for col in SEARCH_COLUMNS:
        value = facts.get(col)
        if col == "risk_level" and not str(value or ""):
            value = "unknown"
        parts.append(str(value or "").lower())
    return SEARCH_SEPARATOR.join(parts)
