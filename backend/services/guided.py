"""Guided mode: three questions, one answer (static/instrument-guided.js, GET /api/public/guided/{domain}).

The front page's switch "Just answer 3 questions" asks for a domain, who is asking and what the
site carries, then shows one screen: the grade, the risk sentence for that kind of data, the
deadline and exactly one next action matched to who is asking. Nothing here is new data:

  - the grade is the public grade's stored check (services/public_grade.py). The page runs that
    check first through GET /api/public/grade/<domain>, which keeps its own budgets, SSRF guard and
    opt-out; this module only reads what that check stored, and never checks anything itself;
  - the sentence is services/risk_sentence.build, with the Shelf-Life kind of data picked (or the
    same assumed default when the visitor says "Not sure");
  - the deadline is services/board_slide._deadline, the board slide's own rule ("Overdue since
    2025", or just "Overdue" when that year is decades back, "Now", "2030 to 2035" or "Met"), for this one host;
  - the supplier's note is services/vendor_check.note, word for word as on a vendor report.

Roles and their one action (ROLE_ACTIONS): ``it`` -> Make it safe (the recipe for the host's own
stack and the live re-check on its record), ``supplier`` -> Send them this note, ``board`` -> a
printable one-page summary of the same answer. The editable board slide is made from an
organisation's own scans and needs an account; the answer says so plainly instead of routing round it.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

ROLES = ("it", "supplier", "board")
#: The data kinds the third question offers: Shelf-Life short ids, in the order shown. "" is "Not sure".
DATA_CHOICES = (
    ("personal", "Personal data", "Names, emails, accounts"),
    ("health", "Health records", "Patients, prescriptions, care"),
    ("financial", "Payments or finance", "Cards, accounts, transactions"),
    ("auth", "Passwords and keys", "Logins, API keys, tokens"),
    ("trade", "Trade secrets", "Designs, plans, source code"),
    ("", "Not sure", "Morrow assumes personal data"),
)
ROLE_ACTIONS = {
    "it": {"kind": "make_safe", "label": "Make it safe"},
    "supplier": {"kind": "note", "label": "Send them this note"},
    "board": {"kind": "summary", "label": "Print the one-page summary"},
}
BOARD_SLIDE_NOTE = ("The editable board slide (PowerPoint or PDF) is built from your own organisation's scans, "
                    "so it needs a free account. This page prints the same answer for one site.")


class GuidedError(Exception):
    def __init__(self, status_code: int, code: str, detail: str):
        super().__init__(detail)
        self.status_code, self.code, self.detail = status_code, code, detail


def _risk_inputs(result: Dict[str, Any]) -> Dict[str, Any]:
    """A stored public grade in the risk sentence's terms (as gradeRiskQ in instrument.js)."""
    ex = result.get("exposure") or {}
    k = result.get("risk") or {}
    state = k.get("state")
    if not state:
        if ex.get("recorded_traffic_at_risk") is False:
            state = "safe"
        elif ex.get("recorded_traffic_at_risk") and not ex.get("decrypt_year_low"):
            state = "no_tls"
        else:
            state = "at_risk"
    fixable = k.get("fixable")
    if fixable is None:
        fixable = len(result.get("settings_to_fix") or []) or (0 if state == "safe" else (1 if result.get("fixes") else 0))
    observed = not (state == "at_risk" and (result.get("key_exchange") or {}).get("observed") is False)
    return {"state": state, "fixable": fixable, "observed": observed}


def answer(domain: str, role: str = "", data: str = "", jur: str = "", base_url: str = "",
           now: Optional[datetime] = None) -> Dict[str, Any]:
    from routers.instrument import domain_segment
    from services import board_slide, public_check, public_grade, risk_sentence, vendor_check

    host = domain_segment(domain)
    if not host:
        raise GuidedError(400, "bad_domain", "Type a domain like example.com.")
    if public_check.opted_out(host):
        raise GuidedError(403, "opted_out", f"{host} has opted out of Morrow's checks, so there is no answer to show.")
    result = public_grade.latest(host)
    if not result:
        raise GuidedError(404, "not_checked", f"{host} has not been checked yet. Run the check first.")
    role = role if role in ROLES else "it"
    now = now or datetime.now(timezone.utc)
    q = _risk_inputs(result)
    risk = risk_sentence.build(host, q["state"], q["fixable"], data or None, jur or None, observed=q["observed"], now=now)
    counts = {"safe": 1 if q["state"] == "safe" else 0, "at_risk": 1 if q["state"] in ("at_risk", "no_tls") else 0,
              "unknown": 1 if q["state"] == "unknown" else 0}
    deadline = board_slide._deadline(risk, [], data or None, jur or None, counts, now)
    safe = q["state"] == "safe"
    base = (base_url or "").rstrip("/")
    record = f"/r/{host}"
    action: Dict[str, Any] = dict(ROLE_ACTIONS[role])
    if role == "it":
        action.update({"href": f"/{host}#make-safe",
                       "detail": ("It already uses a quantum-safe key exchange. Its record keeps the proof and re-checks it."
                                  if safe else "The exact change for the server that answers, then a live re-check and a signed proof.")})
        if safe:
            action["label"] = "See the proof"
            action["href"] = record
    elif role == "supplier":
        entry = vendor_check._entry_from_result(host, result)
        if safe:
            action.update({"kind": "note_none", "label": "Nothing to ask them", "text": "",
                           "detail": f"{host} already uses a quantum-safe key exchange. Keep the record link for your files.",
                           "href": record})
        else:
            action.update({"text": vendor_check.note(entry, base),
                           "detail": "A short, polite note to send them yourself. Morrow sends nothing."})
    else:
        action.update({"detail": BOARD_SLIDE_NOTE, "account_href": "/ui/"})
    return {
        "domain": host, "role": role, "grade": result.get("grade"), "state": q["state"], "safe": safe,
        "checked_at": result.get("scanned_at"),
        "key_exchange": (result.get("key_exchange") or {}).get("group") or None,
        "sentence": risk["sentence"], "assumption": risk.get("assumption"), "estimate": risk.get("estimate"),
        "data": risk.get("data"), "deadline": deadline, "action": action, "record": record,
        "choices": {"roles": list(ROLES), "data": [{"short": s, "label": label, "hint": h} for s, label, h in DATA_CHOICES]},
    }
