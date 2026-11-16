"""The quantum threat board: public evidence of how close a cryptographically relevant quantum computer is.

Served at /threat (the page, static/instrument-threat.js), /api/public/threat (JSON) and
/api/public/threat.atom (one entry per edition of the dataset).

The evidence is one curated, versioned file, data/threat-board/threat-board.json, checked against
data/threat-board/threat-board.schema.json. Every entry cites its primary source with a verbatim
quote, the date it was published and the date it was checked; vendor announcements are labelled
as claims, and entries marked ``verified: false`` are listed but never charted or used in an estimate.

Nothing here fetches anything. The estimate Morrow quotes everywhere (services/decrypt_window: the
risk sentence, the harvest clock, the public grade) is read from the file's expert-survey entry
named in ``estimate.survey``, so it changes only when someone edits the file and the change is
reviewed in git. The file is loaded like the Shelf-Life catalogue: its SHA-256 must equal both the
``.sha256`` file next to it and :data:`EXPECTED_SHA256` pinned here, so an edit has to touch all
three. To publish a new edition: edit the JSON, bump ``version``, add a ``changes`` entry, then
update the checksum file and :data:`EXPECTED_SHA256`.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
from datetime import date, datetime, timezone
from typing import Any, Dict, List, Optional
from xml.sax.saxutils import escape

logger = logging.getLogger(__name__)

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "threat-board")
DATA_FILE = "threat-board.json"
SCHEMA_FILE = "threat-board.schema.json"
#: SHA-256 of the published edition. Pinned here as well as read from threat-board.json.sha256.
EXPECTED_SHA256 = "92185b71a383ab83c66b183b08a87232664bbedc652b2ff84f46fa1067881011"
PAGE_PATH = "/threat"
SECTIONS = ("machines", "attack_cost", "deadlines", "surveys")
#: An entry not re-checked for this long is shown as stale (its source may have moved or changed).
STALE_AFTER_DAYS = 365
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,80}$")


class DatasetError(Exception):
    """The dataset is missing, does not match its checksum, or fails validation."""


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _schema(directory: str) -> Optional[Dict[str, Any]]:
    try:
        with open(os.path.join(directory, SCHEMA_FILE), "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def validate(doc: Any, schema: Optional[Dict[str, Any]] = None) -> List[str]:
    """Every problem with a dataset, as plain sentences. An empty list means it is usable."""
    errors: List[str] = []
    if schema is not None:
        try:
            import jsonschema

            for err in sorted(jsonschema.Draft202012Validator(schema).iter_errors(doc), key=lambda e: list(e.path)):
                where = "/".join(str(p) for p in err.path) or "(top)"
                errors.append(f"{where}: {err.message}")
        except ImportError:  # pragma: no cover - jsonschema is a runtime requirement
            pass
    if not isinstance(doc, dict) or not isinstance(doc.get("entries"), list):
        return errors + ["the dataset has no entries list"]
    seen = set()
    for i, e in enumerate(doc["entries"]):
        if not isinstance(e, dict):
            errors.append(f"entries/{i}: not an object")
            continue
        ident = str(e.get("id") or "")
        if not _ID_RE.match(ident):
            errors.append(f"entries/{i}: bad id {ident!r}")
        if ident in seen:
            errors.append(f"{ident}: duplicate id")
        seen.add(ident)
        if not str(e.get("source_url") or "").startswith("https://"):
            errors.append(f"{ident}: no https source_url")
        if not e.get("date_checked"):
            errors.append(f"{ident}: no date_checked")
        if e.get("verified") is True:
            if not str(e.get("quote") or "").strip():
                errors.append(f"{ident}: verified but has no quote")
            if not e.get("date_published"):
                errors.append(f"{ident}: verified but has no date_published")
        elif e.get("chart"):
            errors.append(f"{ident}: unverified entries are never charted")
        if e.get("section") == "deadlines" and e.get("verified") and not e.get("deadline"):
            errors.append(f"{ident}: a deadline with no date")
    est = doc.get("estimate") if isinstance(doc.get("estimate"), dict) else {}
    survey = next((e for e in doc["entries"] if isinstance(e, dict) and e.get("id") == est.get("survey")), None)
    if not survey:
        errors.append("estimate.survey names no entry")
    else:
        if survey.get("section") != "surveys" or survey.get("verified") is not True:
            errors.append("estimate.survey must be a verified survey entry")
        horizons = {h.get("years") for h in survey.get("horizons") or [] if isinstance(h, dict)}
        for key in ("low_horizon_years", "likely_horizon_years"):
            if est.get(key) not in horizons:
                errors.append(f"estimate.{key} is not a horizon the survey reports")
        if not isinstance(survey.get("survey_year"), int):
            errors.append("the estimate's survey has no survey_year")
    if isinstance(est.get("low_horizon_years"), int) and isinstance(est.get("likely_horizon_years"), int):
        if est["low_horizon_years"] > est["likely_horizon_years"]:
            errors.append("estimate: the low horizon is later than the likely one")
    versions = [c.get("version") for c in doc.get("changes") or [] if isinstance(c, dict)]
    if doc.get("version") not in versions:
        errors.append("the current version has no entry in changes")
    return errors


def load(directory: Optional[str] = None, expected: Optional[str] = EXPECTED_SHA256) -> Dict[str, Any]:
    """Read, verify and validate the dataset. Raises DatasetError; never returns a bad file."""
    directory = directory or DATA_DIR
    path = os.path.join(directory, DATA_FILE)
    try:
        with open(path, "rb") as fh:
            data = fh.read()
        with open(path + ".sha256", "r", encoding="ascii") as fh:
            published = (fh.read().split() or [""])[0].strip().lower()
    except OSError as exc:
        raise DatasetError(f"cannot read {DATA_FILE}: {exc.strerror or exc}") from exc
    actual = sha256_of(data)
    if actual != published:
        raise DatasetError(f"{DATA_FILE} does not match {DATA_FILE}.sha256 ({actual[:12]} != {published[:12]})")
    if expected and actual != expected.lower():
        raise DatasetError(f"{DATA_FILE} is not the pinned edition ({actual[:12]} != {expected[:12]})")
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise DatasetError(f"{DATA_FILE} is not valid JSON: {exc}") from exc
    errors = validate(doc, _schema(directory))
    if errors:
        raise DatasetError(f"{DATA_FILE} is not valid: " + "; ".join(errors[:5]))
    doc["_sha256"] = actual
    return doc


_lock = threading.Lock()
_cache: Dict[str, Any] = {}


def dataset() -> Optional[Dict[str, Any]]:
    """The verified dataset, loaded once per process; None (and logged) when it is unusable."""
    with _lock:
        if "doc" not in _cache:
            try:
                _cache["doc"], _cache["error"] = load(), None
            except DatasetError as exc:
                logger.error("threat board dataset refused: %s", exc)
                _cache["doc"], _cache["error"] = None, str(exc)
        return _cache["doc"]


def load_error() -> Optional[str]:
    dataset()
    return _cache.get("error")


def _entry(doc: Dict[str, Any], ident: str) -> Optional[Dict[str, Any]]:
    return next((e for e in doc["entries"] if e.get("id") == ident), None)


def estimate_from(doc: Dict[str, Any]) -> Dict[str, Any]:
    """The CRQC estimate the dataset's chosen survey gives: the years Morrow quotes everywhere."""
    est = doc["estimate"]
    survey = _entry(doc, est["survey"])
    horizons = {h["years"]: h for h in survey["horizons"]}
    lo_h, li_h = horizons[est["low_horizon_years"]], horizons[est["likely_horizon_years"]]
    low = survey["survey_year"] + est["low_horizon_years"]
    likely = survey["survey_year"] + est["likely_horizon_years"]

    def pct(h: Dict[str, Any]) -> str:
        return f"{h['low']}-{h['high']}%" if h.get("high") is not None else f"about {h['low']}%"

    return {
        "low": low, "likely": likely, "high": likely + int(est["outer_bound_years"]),
        "low_probability": pct(lo_h), "likely_probability": pct(li_h),
        "low_label": lo_h.get("label") or "", "likely_label": li_h.get("label") or "",
        "survey_id": survey["id"], "survey_year": survey["survey_year"], "experts": survey.get("experts"),
        "question": survey.get("question"), "source_url": survey["source_url"], "source_label": survey["source_title"],
        "date_published": survey["date_published"], "quote": survey["quote"],
        "outer_bound_note": est.get("outer_bound_note") or "",
        "dataset_version": doc["version"], "dataset_sha256": doc.get("_sha256"),
    }


def expert_estimate() -> Optional[Dict[str, Any]]:
    doc = dataset()
    return estimate_from(doc) if doc else None


def _stale(e: Dict[str, Any], today: date) -> bool:
    try:
        checked = datetime.strptime(str(e.get("date_checked")), "%Y-%m-%d").date()
    except ValueError:
        return True
    return (today - checked).days > STALE_AFTER_DAYS


def _public(e: Dict[str, Any], today: date) -> Dict[str, Any]:
    out = dict(e)
    out["stale"] = _stale(e, today)
    return out


def headline(est: Dict[str, Any]) -> Dict[str, str]:
    sentence = (f"Experts put it at more likely than not by about {est['likely']}, "
                f"and quite possible by about {est['low']}.")
    why = (f"Morrow says about {est['low']} because the {est['source_label']} (published {est['date_published']}) "
           f"asked {est['experts']} experts in {est['survey_year']} how likely it is that {est['question']} will exist. "
           f"Averaged, they gave {est['low_probability']} within {est['low'] - est['survey_year']} years "
           f"(by {est['low']}) and {est['likely_probability']} within {est['likely'] - est['survey_year']} years "
           f"(by {est['likely']}). The range runs from a cautious to a generous reading of their answers. "
           f"Morrow dates recorded traffic from {est['low']}, the earlier year, because a secret has to last "
           f"until the first moment someone could read it.")
    return {"sentence": sentence, "why": why}


def board(today: Optional[date] = None) -> Dict[str, Any]:
    """Everything /threat shows. Raises DatasetError when the dataset is unusable."""
    doc = dataset()
    if not doc:
        raise DatasetError(load_error() or "the dataset is unavailable")
    today = today or datetime.now(timezone.utc).date()
    est = estimate_from(doc)
    sections: Dict[str, List[Dict[str, Any]]] = {s: [] for s in SECTIONS}
    unverified = []
    for e in doc["entries"]:
        if e.get("verified"):
            sections[e["section"]].append(_public(e, today))
        else:
            unverified.append({k: e.get(k) for k in ("id", "section", "title", "org", "source_url", "note", "date_checked")})
    for s in ("machines", "attack_cost", "surveys"):
        sections[s].sort(key=lambda e: str(e.get("date_published") or ""))
    sections["deadlines"].sort(key=lambda e: (str(e.get("deadline")), e["id"]))
    return {
        "title": doc["title"], "version": doc["version"], "date": doc["date"], "sha256": doc["_sha256"],
        "policy": doc["policy"], "license": doc.get("license"), "editors": doc["editors"],
        "headline": headline(est), "estimate": est, "sections": sections, "unverified": unverified,
        "stale": [e["id"] for s in sections.values() for e in s if e["stale"]],
        "changes": doc["changes"], "page": PAGE_PATH,
        "feed": "/api/public/threat.atom", "dataset": "/api/public/threat/dataset.json",
        "source_file": "backend/data/threat-board/threat-board.json",
    }


def raw_dataset() -> bytes:
    """The exact verified file, for anyone who wants to check the checksum themselves."""
    doc = dataset()
    if not doc:
        raise DatasetError(load_error() or "the dataset is unavailable")
    with open(os.path.join(DATA_DIR, DATA_FILE), "rb") as fh:
        data = fh.read()
    if sha256_of(data) != doc["_sha256"]:
        raise DatasetError("the dataset changed on disk after it was verified")
    return data


def atom(base_url: str) -> str:
    """One Atom entry per edition of the dataset (its ``changes`` list), newest first."""
    doc = dataset()
    if not doc:
        raise DatasetError(load_error() or "the dataset is unavailable")
    base = base_url.rstrip("/")
    changes = sorted(doc["changes"], key=lambda c: (c["date"], c["version"]), reverse=True)
    updated = changes[0]["date"] + "T00:00:00Z"
    parts = ['<?xml version="1.0" encoding="utf-8"?>', '<feed xmlns="http://www.w3.org/2005/Atom">',
             "<id>urn:morrow:threat-board</id>", "<title>Morrow quantum threat board: dataset changes</title>",
             "<updated>" + escape(updated) + "</updated>", "<author><name>SOQLAB Morrow</name></author>",
             '<link rel="self" type="application/atom+xml" href="' + escape(base + "/api/public/threat.atom") + '"/>',
             '<link rel="alternate" type="text/html" href="' + escape(base + PAGE_PATH) + '"/>']
    for c in changes:
        parts.append("<entry><id>urn:morrow:threat-board:" + escape(c["version"]) + "</id>"
                     "<title>Edition " + escape(c["version"]) + "</title>"
                     "<updated>" + escape(c["date"]) + "T00:00:00Z</updated>"
                     "<summary>" + escape(c["summary"]) + "</summary>"
                     '<link href="' + escape(base + PAGE_PATH) + '"/></entry>')
    parts.append("</feed>")
    return "\n".join(parts) + "\n"
