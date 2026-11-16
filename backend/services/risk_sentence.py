"""Your quantum risk in one sentence, at the top of every scan report.

"Your personal data sent to api.example.com today could be read from about 2035 (expert estimates:
2035 to 2040), but it needs to stay private until 2096. Fix 2 settings and traffic from then on
can't be read with a quantum computer."

Nothing here is new arithmetic. The sentence joins three things Morrow already computes:
  * the harvest clock (services/decrypt_window.harvest and CRQC_ESTIMATE): from which year a
    recording of today's traffic could be read; the year is an estimate, so it is always "about",
    and the survey's range is quoted with it;
  * the Shelf-Life catalogue (services/shelf_life.py): how long the kind of data must stay private.
    The person picks the kind of data; until they do, the sentence says which one it assumed
    (personal data, under the law the domain's country-code TLD suggests);
  * how many settings fix it: the public grade's ``settings_to_fix`` (services/public_grade.py), or
    on a console scan the findings that carry a remediation.

A host that is already safe gets that answer instead. The builder is pure (the clock is read only
for the current year) and is served at GET /api/public/risk-sentence, so the public check, the
console and the instrument's signed-in views all show the same words.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from services import decrypt_window, shelf_life

STATES = ("safe", "at_risk", "no_tls", "unknown")
DEFAULT_CATEGORY = "personal-data-general"
MAX_OTHERS = 100000
_HOST_RE = re.compile(r"^[A-Za-z0-9._:\[\]-]{1,253}$")


def clean_host(value: Any) -> Optional[str]:
    """A host name, IP address or host:port, or None. The sentence quotes it, so nothing else gets in."""
    text = str(value or "").strip().rstrip(".")
    return text.lower() if _HOST_RE.match(text) and any(c.isalnum() for c in text) else None


def _lower_first(text: str) -> str:
    return text[0].lower() + text[1:] if len(text) > 1 and text[0].isupper() and text[1].islower() else text


def _settings(n: int) -> str:
    return f"{n} setting" if n == 1 else f"{n} settings"


def _data(category: Any, jurisdiction: Any, host: str) -> Optional[Dict[str, Any]]:
    """The Shelf-Life entry the sentence uses, and whether it was chosen or assumed. None without the catalogue."""
    payload = shelf_life.public_payload()
    if not payload.get("available"):
        return None
    ids = [c["id"] for c in payload["categories"]]
    chosen = shelf_life.resolve_category(category, ids)
    cid = chosen or DEFAULT_CATEGORY
    jur_in = str(jurisdiction or "").strip().upper()
    jur_chosen = jur_in if jur_in in shelf_life.CHOOSABLE else None
    bare_host = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
    jur = jur_chosen or shelf_life.jurisdiction_for_domain(bare_host)
    entries = {e["id"]: e for e in payload["entries"]}
    entry, code = shelf_life.pick(entries, cid, jur)
    if entry is None:
        return None
    cat = next(c for c in payload["categories"] if c["id"] == cid)
    names = {j["code"]: j for j in payload["jurisdictions"]}
    return {
        "category": cid, "short": cat["short"], "label": cat["label"], "plural": bool(cat["plural"]),
        "jurisdiction": code, "jurisdiction_short": names.get(code, {}).get("short", code),
        "requested_jurisdiction": jur, "assumed": chosen is None, "jurisdiction_assumed": jur_chosen is None,
        "min_years": entry["min"], "max_years": entry["max"], "years": entry["years"],
        "open_ended": bool(entry["open_ended"]), "entry": entry["id"], "edition": payload["edition"],
        "source_url": payload["attribution"]["source_url"],
    }


def _choices() -> Dict[str, List[Dict[str, str]]]:
    payload = shelf_life.public_payload()
    if not payload.get("available"):
        return {"categories": [], "jurisdictions": []}
    return {"categories": [{"id": c["id"], "short": c["short"], "label": c["label"]} for c in payload["categories"]],
            "jurisdictions": [{"code": j["code"], "short": j["short"]} for j in payload["jurisdictions"] if j["choosable"]]}


def _assumption(data: Optional[Dict[str, Any]]) -> str:
    if data is None:
        return "Morrow could not load the Shelf-Life catalogue, so the sentence does not say how long the data must stay private."
    span = (f"{data['min_years']} years" if data["min_years"] == data["max_years"] else
            f"{data['min_years']} to {data['max_years']}{'+' if data['open_ended'] else ''} years")
    where = "" if data["jurisdiction"] == "INT" else f" under {data['jurisdiction_short']} law"
    lead = "Assumes" if data["assumed"] else "For"
    return (f"{lead} {_lower_first(data['label'])}{where}: Shelf-Life v{data['edition']} says {span}; "
            f"the sentence uses {data['years']}." + (" Pick the kind of data you send to change it." if data["assumed"] else ""))


def build(host: Any, state: str, fixable: Any = 0, data: Any = None, jurisdiction: Any = None,
          observed: bool = True, others: Any = 0, now: Optional[datetime] = None) -> Dict[str, Any]:
    """The sentence and everything it was built from.

    ``state``: ``safe`` (the key exchange includes ML-KEM), ``at_risk`` (classical, or not observed),
    ``no_tls`` (nothing encrypted) or ``unknown`` (the check did not reach the host's TLS).
    ``fixable``: how many settings (or remediable findings) fix it. ``others``: further endpoints in
    the same scan, named only as a count. ``observed``: False when the key exchange was not seen and
    is therefore assumed classical.
    """
    name = clean_host(host) or "this host"
    state = state if state in STATES else "unknown"
    try:
        n = max(0, min(999, int(fixable or 0)))
    except (TypeError, ValueError):
        n = 0
    try:
        more = max(0, min(MAX_OTHERS, int(others or 0)))
    except (TypeError, ValueError):
        more = 0
    where = name if not more else f"{name} and {more} other endpoint{'s' if more != 1 else ''}"
    d = _data(data, jurisdiction, name)
    est = decrypt_window.CRQC_ESTIMATE
    low, likely = int(est["low"]), int(est["likely"])
    plural = bool(d and d["plural"])
    what = f"your {_lower_first(d['label'])}" if d else "data"
    subject = what[0].upper() + what[1:]
    it, need, be = ("they", "need", "are") if plural else ("it", "needs", "is")
    clock = decrypt_window.harvest(state != "no_tls", state == "safe", d["years"] if d else 0, crqc_year=low, now=now)
    secret_until = clock["secret_until"] if d else None

    if state == "safe":
        sentence = (f"{subject} on {where} {be} already quantum-safe: traffic recorded today can't be read later "
                    "with a quantum computer.")
        if n:
            sentence += f" {_settings(n)} still {'needs' if n == 1 else 'need'} attention, but none of them change that."
    elif state == "no_tls":
        sentence = f"{subject} sent to {where} {be} not encrypted at all: anyone on the path can read {'them' if plural else 'it'} today."
        sentence += (f" Fix {_settings(n)} to encrypt {'them' if plural else 'it'}." if n else
                     " Turn on HTTPS first; Morrow then shows the exact settings.")
    elif state == "unknown":
        sentence = (f"Morrow could not read {where}'s encryption, so it can't say when {what} sent to it could be read. "
                    "Re-check it to get an answer.")
    else:
        sentence = f"{subject} sent to {where} today could be read from about {low} (expert estimates: {low} to {likely})"
        if d and clock["exposed"]:
            sentence += f", but {it} {need} to stay private until {secret_until}."
        elif d:
            sentence += f", after {it} {need} to stay private (until {secret_until})."
        else:
            sentence += "."
        sentence += (f" Fix {_settings(n)} and traffic from then on can't be read with a quantum computer." if n else
                     " No server setting Morrow knows of fixes this yet; it depends on your provider.")
        if not observed:
            sentence += " Morrow couldn't see the key exchange, so it assumes a classical one."

    return {
        "sentence": sentence,
        "state": state,
        "host": name,
        "others": more,
        "fixable": n,
        "readable_from": low if state == "at_risk" else (clock["year"] if state == "no_tls" else None),
        "estimate": {"low": low, "likely": likely, "high": int(est["high"]), "is_estimate": True,
                     "source_url": decrypt_window.EXPOSURE_SOURCE_URL, "source_label": decrypt_window.EXPOSURE_SOURCE_LABEL,
                     "board_url": decrypt_window.THREAT_BOARD_URL},
        "secret_until": secret_until,
        "exposed": bool(clock["exposed"]) if d and state in ("at_risk", "no_tls") else (False if state == "safe" else None),
        "data": d,
        "assumption": _assumption(d),
        "choices": _choices(),
    }


# ── from Morrow's two kinds of result ────────────────────────────────────────


def settings_to_fix(result: Dict[str, Any]) -> int:
    """How many settings fix a public grade result. Older stored results lack the field: derived from the rest."""
    given = result.get("settings_to_fix")
    if isinstance(given, list):
        return len(given)
    kx = result.get("key_exchange") or {}
    versions = (result.get("tls") or {}).get("versions") or {}
    tls = bool((result.get("tls") or {}).get("negotiated")) or any(versions.values())
    reasons = " ".join(str(r) for r in result.get("reasons") or []).lower()
    cert = result.get("certificate") or {}
    needs = [
        tls and not kx.get("post_quantum"),
        bool(versions.get("1.0") or versions.get("1.1")),
        "weak ciphers" in reasons or "weak tls 1.2 ciphers" in reasons or "rsa key transport" in reasons,
        tls and (cert.get("verified") is False or "certificate expires in" in reasons or "certificate is expired" in reasons),
    ]
    return sum(1 for x in needs if x)


def state_of_grade(result: Dict[str, Any]) -> str:
    ex = result.get("exposure") or {}
    if ex.get("recorded_traffic_at_risk") is False:
        return "safe"
    if ex.get("recorded_traffic_at_risk") and not ex.get("decrypt_year_low"):
        return "no_tls"
    return "at_risk"


def for_grade(result: Dict[str, Any], data: Any = None, jurisdiction: Any = None,
              now: Optional[datetime] = None) -> Dict[str, Any]:
    """The sentence for a public grade result (/api/public/grade/{domain})."""
    kx = result.get("key_exchange") or {}
    state = state_of_grade(result)
    return build(result.get("domain"), state, settings_to_fix(result), data, jurisdiction,
                 observed=bool(kx.get("observed", True)) or state != "at_risk", now=now)
