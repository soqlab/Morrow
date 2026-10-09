"""
Cryptographic Key Map

Places the keys observed in your scans on a world map by the country their
hostname's country-code TLD indicates, with a heuristic quantum-weakness score
for each key algorithm.

Shown: host, port, key type and size, TLS version (as scanned), the country
implied by the hostname's ccTLD (null when there is none), and the heuristic
risk score.

Not shown: any estimate of which agency or country has recorded the traffic.
The platform has no sourced basis for per-adversary harvest probabilities.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional, Tuple

from services.model_basis import model_basis as _model_basis


# ── Country-code TLD → country (plus US-restricted sponsored TLDs) ────────────
_TLD_TO_COUNTRY: Dict[str, str] = {
    ".cn": "CN",
    ".ru": "RU", ".su": "RU",
    ".de": "DE",
    ".uk": "GB",
    ".us": "US", ".gov": "US", ".mil": "US", ".edu": "US",
    ".au": "AU",
    ".ca": "CA",
    ".fr": "FR",
    ".jp": "JP",
    ".kr": "KR",
    ".sg": "SG",
    ".tw": "TW",
    ".hk": "HK",
    ".in": "IN",
    ".br": "BR",
    ".ir": "IR",
    ".ua": "UA",
    ".pl": "PL",
    ".nz": "NZ",
    ".il": "IL",
    ".sa": "SA",
    ".ae": "AE",
}

# Approximate country centres (map placement only)
_COUNTRY_COORDS: Dict[str, Tuple[float, float]] = {
    "CN": (35.0, 105.0), "TW": (23.7, 121.0), "HK": (22.3, 114.2),
    "SG": (1.3, 103.8), "KR": (37.0, 128.0), "JP": (36.0, 138.0),
    "AU": (-25.0, 133.0), "NZ": (-41.0, 174.0),
    "US": (38.0, -97.0), "CA": (56.0, -96.0),
    "GB": (54.0, -2.0), "DE": (51.0, 10.0), "FR": (46.0, 2.0),
    "RU": (60.0, 100.0), "UA": (49.0, 32.0), "PL": (52.0, 20.0),
    "IN": (20.0, 77.0), "IR": (32.0, 53.0),
    "SA": (24.0, 45.0), "AE": (24.0, 54.0), "IL": (31.0, 35.0),
    "BR": (-15.0, -47.0),
}


def _infer_country(host: str) -> Optional[str]:
    """Country from the hostname's TLD, or None. Hosting location is not inferred."""
    host = (host or "").lower().strip().rstrip(".")
    for tld, country in sorted(_TLD_TO_COUNTRY.items(), key=lambda x: -len(x[0])):
        if host.endswith(tld):
            return country
    return None


def _risk_score(key_type: str, key_bits: Optional[int]) -> Tuple[Optional[float], str]:
    """Heuristic 0.0 (quantum-safe) … 1.0 (weakest). None when the key type was not observed."""
    kt = (key_type or "").lower()
    if not kt:
        return None, "key_type_not_observed"
    if "ml-kem" in kt or "kyber" in kt or "dilithium" in kt or "ml-dsa" in kt or "slh" in kt:
        return 0.02, "post_quantum"
    if "rsa" in kt:
        if not key_bits:
            return 0.85, "rsa_size_not_observed"
        if key_bits <= 1024: return 1.0, "rsa"
        if key_bits <= 2048: return 0.85, "rsa"
        if key_bits <= 3072: return 0.70, "rsa"
        return 0.55, "rsa"
    if "ec" in kt or "ecdsa" in kt or "ecdh" in kt:
        if not key_bits:
            return 0.90, "ec_size_not_observed"
        if key_bits <= 256: return 0.90, "ec"
        if key_bits <= 384: return 0.78, "ec"
        return 0.65, "ec"
    if "dh" in kt:
        return 0.80, "dh"
    return 0.70, "other_classical"


def _jitter(host: str, salt: str) -> float:
    digest = hashlib.sha256(f"{salt}:{host}".encode()).digest()
    return (digest[0] % 100) / 300.0


def dark_matter_model_basis() -> Dict[str, Any]:
    return _model_basis(
        kind="model",
        summary=(
            "Observed keys from your scans placed by hostname TLD, with a heuristic weakness score; "
            "it does not estimate who, if anyone, has recorded your traffic."
        ),
        assumptions=[
            "Country comes only from the hostname's country-code TLD (.gov, .mil and .edu map to US); "
            "hosting location is not inferred, so most .com/.net/.io hosts have no country.",
            "Map coordinates are country centres plus a small fixed per-host offset so points do not overlap.",
            "risk_score is a heuristic by algorithm family and key size (RSA-2048 0.85, P-256 0.90, PQC 0.02); "
            "null when the scan did not record a key type.",
        ],
        sources=[],
        as_of="2026-09",
    )


def build_dark_matter_map(
    scan_results_list: List[List[Dict[str, Any]]],
) -> Dict[str, Any]:
    """
    Build the key map from scan results.

    Returns key records with (when derivable) country and coordinates, per-country
    aggregates, and summary counts.
    """
    key_records: List[Dict[str, Any]] = []
    country_stats: Dict[str, Dict[str, Any]] = {}

    for results in scan_results_list:
        for r in (results or []):
            if r.get("error"):
                continue
            host = str(r.get("host") or "")
            port = int(r.get("port") or 0) or None
            key_type = str(r.get("cert_key_type") or r.get("key_type") or "")
            key_bits = int(r.get("cert_key_bits") or r.get("key_bits") or 0) or None
            tls_version = str(r.get("tls_version") or "")

            country = _infer_country(host)
            coords = _COUNTRY_COORDS.get(country) if country else None
            risk, risk_basis = _risk_score(key_type, key_bits)

            rec = {
                "id": hashlib.md5(f"{host}:{port}".encode(), usedforsecurity=False).hexdigest()[:12],
                "host": host,
                "port": port,
                "key_type": key_type,
                "key_bits": key_bits,
                "tls_version": tls_version,
                "country": country,
                "country_source": "tld" if country else None,
                "lat": round(coords[0] + _jitter(host, "lat"), 4) if coords else None,
                "lon": round(coords[1] + _jitter(host, "lon"), 4) if coords else None,
                "risk_score": round(risk, 3) if risk is not None else None,
                "risk_basis": risk_basis,
            }
            key_records.append(rec)

            if country:
                cs = country_stats.setdefault(country, {
                    "country": country,
                    "lat": coords[0] if coords else None,
                    "lon": coords[1] if coords else None,
                    "key_count": 0, "scored_key_count": 0, "total_risk": 0.0,
                })
                cs["key_count"] += 1
                if risk is not None:
                    cs["scored_key_count"] += 1
                    cs["total_risk"] += risk

    country_summary = []
    for cs in country_stats.values():
        n = cs["scored_key_count"]
        cs["avg_risk"] = round(cs["total_risk"] / n, 3) if n else None
        cs["total_risk"] = round(cs["total_risk"], 3)
        country_summary.append(cs)

    total_keys = len(key_records)
    high_risk = sum(1 for k in key_records if (k["risk_score"] or 0) >= 0.80)

    return {
        "key_records": key_records,
        "country_summary": country_summary,
        "meta": {
            "total_keys_mapped": total_keys,
            "high_risk_keys": high_risk,
            "countries_covered": len(country_stats),
            "keys_without_country": sum(1 for k in key_records if not k["country"]),
            "keys_without_key_type": sum(1 for k in key_records if not k["key_type"]),
        },
        "model_basis": dark_matter_model_basis(),
    }
