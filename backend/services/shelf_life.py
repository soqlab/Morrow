"""Shelf-Life: how long a kind of data must stay private, by jurisdiction. Served at /api/public/shelf-life.

The harvest clock (services/decrypt_window.harvest, static/instrument.js) asks "how long must the
data stay private?". Shelf-Life (https://github.com/soqlab/shelf-life, CC BY 4.0, SOQLAB and
contributors) answers it per data category and jurisdiction, with the legal basis, reasoning and
citations. Edition 0.1 is vendored, unchanged, in data/shelf-life/ (see the NOTICE there) so it
works offline.

The file is checked before use: its SHA-256 must equal both the pinned :data:`EXPECTED_SHA256` and
the published ``v0.1.json.sha256`` next to it. A file that does not match is logged and not used;
the clock then falls back to its own example buttons. Loaded once per process.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

EDITION = "0.1"
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "shelf-life")
CATALOGUE_FILE = "v0.1.json"
#: SHA-256 of the published edition 0.1 file. Pinned here as well as read from v0.1.json.sha256, so
#: a changed catalogue with a regenerated checksum file is still refused.
EXPECTED_SHA256 = "0ef2f4a341acaa803ae9833060465466cc9cfb2a3aea6852922cc0351671541a"
SOURCE_URL = "https://github.com/soqlab/shelf-life"
LICENCE = "CC BY 4.0"
LICENCE_URL = "https://creativecommons.org/licenses/by/4.0/"
TITLE = "Shelf-Life: confidentiality lifetimes of data categories"
AUTHOR = "SOQLAB and contributors"
ATTRIBUTION = (f"Shelf-Life v{EDITION} ({TITLE}) by {AUTHOR}, {SOURCE_URL}, licensed {LICENCE} "
               f"({LICENCE_URL}). No changes made.")

#: How the instrument names each category: a short label and whether it takes "need" or "needs".
#: Categories not listed fall back to the catalogue's own name.
LABELS: Dict[str, Tuple[str, bool]] = {
    "health-records": ("Health records", True),
    "genetic-data": ("Genetic data", False),
    "financial-account-payment": ("Financial and payment data", False),
    "tax-records": ("Tax records", True),
    "employment-hr": ("HR records", True),
    "legal-privileged": ("Privileged legal files", True),
    "government-classified": ("Classified government information", False),
    "trade-secrets": ("Trade secrets", True),
    "biometric-data": ("Biometric data", False),
    "childrens-data": ("Children's data", False),
    "telecom-metadata": ("Telecom metadata", False),
    "auth-secrets": ("Passwords and keys", True),
    "personal-data-general": ("Personal data", False),
}
#: Short names for sentences: "UK health records", "Health records (UK)".
JURISDICTION_SHORT: Dict[str, Tuple[str, str]] = {
    # code: (short name, adjective)
    "EU": ("EU", "EU"), "GB": ("UK", "UK"), "US": ("US", "US"), "DE": ("Germany", "German"),
    "CA": ("Canada", "Canadian"), "AU": ("Australia", "Australian"), "INT": ("any jurisdiction", ""),
}
#: Jurisdictions a person can choose (INT applies on its own when a category has nothing else).
CHOOSABLE = ("EU", "GB", "US", "DE", "CA", "AU")
#: Country-code TLDs whose jurisdiction is obvious. EU member states map to EU (except Germany,
#: which has its own entries); anything else is left to the person's choice.
_EU_MEMBER_TLDS = ("at", "be", "bg", "hr", "cy", "cz", "dk", "ee", "fi", "fr", "gr", "hu", "ie", "it", "lv", "lt",
                   "lu", "mt", "nl", "pl", "pt", "ro", "sk", "si", "es", "se", "eu")
TLD_JURISDICTIONS: Dict[str, str] = {
    **{tld: "EU" for tld in _EU_MEMBER_TLDS},
    "de": "DE", "uk": "GB", "us": "US", "gov": "US", "mil": "US", "ca": "CA", "au": "AU",
}
#: When a category has no entry for the chosen jurisdiction: the jurisdiction-neutral entry, then
#: the wider law that contains it, then these in order.
_PARENT = {"DE": "EU"}
_FALLBACK_ORDER = ("INT", "EU", "US", "GB", "DE", "CA", "AU")
BASIS_WORDS = {
    "legal_minimum": "set by law",
    "legal_retention": "a legal retention period",
    "sector_guidance": "official guidance",
    "reasoned_estimate": "reasoned estimate",
}
#: The harvest clock's dial reaches the longest catalogue value (decrypt_window.SHELF_YEARS_MAX).
YEARS_MAX = 130


class CatalogueError(Exception):
    """The vendored catalogue is missing, unreadable or does not match its checksum."""


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_catalogue(directory: Optional[str] = None, expected: Optional[str] = EXPECTED_SHA256) -> Dict[str, Any]:
    """Read and verify the catalogue. Raises CatalogueError on any mismatch; never returns a bad file."""
    directory = directory or DATA_DIR
    path = os.path.join(directory, CATALOGUE_FILE)
    try:
        with open(path, "rb") as fh:
            data = fh.read()
        with open(path + ".sha256", "r", encoding="ascii") as fh:
            published = (fh.read().split() or [""])[0].strip().lower()
    except OSError as exc:
        raise CatalogueError(f"cannot read {CATALOGUE_FILE}: {exc.strerror or exc}") from exc
    actual = sha256_of(data)
    if actual != published:
        raise CatalogueError(f"{CATALOGUE_FILE} does not match {CATALOGUE_FILE}.sha256 ({actual[:12]} != {published[:12]})")
    if expected and actual != expected.lower():
        raise CatalogueError(f"{CATALOGUE_FILE} is not the pinned edition {EDITION} ({actual[:12]} != {expected[:12]})")
    try:
        cat = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise CatalogueError(f"{CATALOGUE_FILE} is not valid JSON: {exc}") from exc
    if not isinstance(cat, dict) or not isinstance(cat.get("entries"), list) or str(cat.get("edition")) != EDITION:
        raise CatalogueError(f"{CATALOGUE_FILE} is not Shelf-Life edition {EDITION}")
    cat["_sha256"] = actual
    return cat


_lock = threading.Lock()
_loaded: Dict[str, Any] = {}


def catalogue() -> Optional[Dict[str, Any]]:
    """The verified catalogue, loaded once; None (logged once) when it cannot be used."""
    with _lock:
        if "cat" not in _loaded:
            try:
                _loaded["cat"], _loaded["error"] = load_catalogue(), None
            except CatalogueError as exc:
                logger.warning("Shelf-Life catalogue not used, the harvest clock falls back to its examples: %s", exc)
                _loaded["cat"], _loaded["error"] = None, str(exc)
        return _loaded["cat"]


def load_error() -> Optional[str]:
    catalogue()
    return _loaded.get("error")


def reset_cache() -> None:
    with _lock:
        _loaded.clear()
        _payload_cache.clear()


# ── mapping ──────────────────────────────────────────────────────────────────


def short_id(category_id: str, all_ids: List[str]) -> str:
    """The URL form of a category: its first word when that is unique (``health``), else the id."""
    head = category_id.split("-", 1)[0]
    return head if sum(1 for c in all_ids if c.split("-", 1)[0] == head) == 1 else category_id


def resolve_category(value: Any, category_ids: List[str]) -> Optional[str]:
    """``?data=`` to a category id: the id itself or its short form (``health`` -> health-records)."""
    text = str(value or "").strip().lower()
    if not text:
        return None
    if text in category_ids:
        return text
    for cid in category_ids:
        if short_id(cid, category_ids) == text:
            return cid
    return None


def jurisdiction_for_domain(domain: Any) -> Optional[str]:
    """The jurisdiction a domain's country-code TLD makes obvious (example.co.uk -> GB), else None."""
    host = str(domain or "").strip().lower().rstrip(".")
    if "." not in host:
        return None
    return TLD_JURISDICTIONS.get(host.rsplit(".", 1)[-1])


def slider_years(entry: Dict[str, Any]) -> int:
    """The single number the clock uses: ``value`` if given, else ``max`` (the conservative end)."""
    rec = entry.get("recommended_confidentiality_years") or entry
    years = rec.get("value") if rec.get("value") is not None else rec.get("max")
    return max(0, min(YEARS_MAX, int(years if years is not None else rec.get("min") or 0)))


def pick(entries: Dict[str, Dict[str, Any]], category: str, jurisdiction: Optional[str]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """The entry for a category in a jurisdiction, and the jurisdiction it really came from.

    ``entries`` is keyed by ``<category>/<jurisdiction>``. When the jurisdiction has no entry the
    jurisdiction-neutral one is used, then the law that contains it (Germany -> EU), then the first
    of EU, US, UK, Germany, Canada, Australia that has one. Returns (None, None) for an unknown
    category.
    """
    jur = str(jurisdiction or "").upper()
    order = [jur, "INT", _PARENT.get(jur, "")] + list(_FALLBACK_ORDER)
    for code in order:
        if code and f"{category}/{code}" in entries:
            return entries[f"{category}/{code}"], code
    return None, None


# ── the public payload ───────────────────────────────────────────────────────


_payload_cache: Dict[str, Any] = {}


def _trim(entry: Dict[str, Any]) -> Dict[str, Any]:
    rec = entry.get("recommended_confidentiality_years") or {}
    cites = [{"instrument": b.get("instrument"), "provision": b.get("provision"), "url": b.get("url")}
             for b in entry.get("legal_basis") or [] if b.get("status") == "verified" and b.get("url")]
    return {
        "id": entry["id"], "category": entry["data_category"]["id"], "jurisdiction": entry["jurisdiction"]["code"],
        "min": rec.get("min"), "max": rec.get("max"), "value": rec.get("value"),
        "open_ended": bool(rec.get("open_ended")), "basis": rec.get("basis"),
        "basis_words": BASIS_WORDS.get(str(rec.get("basis")), str(rec.get("basis") or "")),
        "confidence": entry.get("confidence"), "years": slider_years(entry), "citations": cites,
    }


def public_payload() -> Dict[str, Any]:
    """What the harvest clock needs, trimmed: categories, jurisdictions, entries and their citation links."""
    if "payload" in _payload_cache:
        return _payload_cache["payload"]
    cat = catalogue()
    attribution = {"title": TITLE, "edition": EDITION, "author": AUTHOR, "licence": LICENCE,
                   "licence_url": LICENCE_URL, "source_url": SOURCE_URL, "changes": "none", "text": ATTRIBUTION}
    if cat is None:
        out = {"available": False, "edition": EDITION, "reason": load_error() or "not loaded", "attribution": attribution}
        _payload_cache["payload"] = out
        return out
    ids = [c["id"] for c in cat.get("categories") or []]
    present = {e["jurisdiction"]["code"] for e in cat["entries"]}
    out = {
        "available": True,
        "edition": EDITION,
        "date": cat.get("date"),
        "sha256": cat["_sha256"],
        "attribution": attribution,
        "method_url": cat.get("method"),
        "disclaimer": cat.get("disclaimer"),
        "counting_convention": cat.get("counting_convention"),
        "years_max": YEARS_MAX,
        "categories": [{"id": c["id"], "short": short_id(c["id"], ids), "name": c["name"],
                        "label": LABELS.get(c["id"], (c["name"], False))[0],
                        "plural": LABELS.get(c["id"], (c["name"], False))[1]} for c in cat["categories"]],
        "jurisdictions": [{"code": j["code"], "name": j["name"],
                           "short": JURISDICTION_SHORT.get(j["code"], (j["code"], j["code"]))[0],
                           "adjective": JURISDICTION_SHORT.get(j["code"], (j["code"], j["code"]))[1],
                           "choosable": j["code"] in CHOOSABLE}
                          for j in cat.get("jurisdictions") or [] if j["code"] in present],
        "tld_jurisdictions": dict(TLD_JURISDICTIONS),
        "fallback_order": list(_FALLBACK_ORDER),
        "parents": dict(_PARENT),
        "entries": [_trim(e) for e in cat["entries"]],
    }
    _payload_cache["payload"] = out
    return out
