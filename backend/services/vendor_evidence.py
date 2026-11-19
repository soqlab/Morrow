"""Vendor evidence packs: for each vendor in a buyer's report that is not quantum-safe, a signed pack
the buyer can send, a proposed contract addendum and ready-made tickets.

What a pack holds, and only this (everything is what Morrow measured, or a link to it):

  * the vendor's domain and what the newest check saw, in the vendor check's own words;
  * the public grade checks of that domain (``public_grade_checks``, newest first): when, in UTC,
    the check id, the key-exchange group the server chose, the TLS versions it accepted, whether
    its certificate verified, the grade and the rubric version, each with the public history link;
  * the registry's dated observations of the same domain (``public_check_observations``), each with
    its citable permalink ``/r/<domain>/at/<id>``;
  * the deadline for the buyer's kind of data: services/board_slide.py's ``_deadline`` (Mosca's
    inequality on the Shelf-Life entry, "Not sure" = the assumed default) with its sources, so the
    pack and the board slide can never disagree for the same inputs;
  * how Morrow measures: ``/about-scanner`` and the public grade's method (docs/PUBLIC_GRADE.md).

The pack's canonical JSON (services/proof_signing.canonical_bytes) is signed with the same Ed25519 +
ML-DSA-65 key set as the quantum-safe proof (services/make_safe.py), under its own context string
``morrow.vendor-evidence.v1``: a proof's signature can never be replayed as an evidence signature,
or the reverse. Anyone can check it offline against ``/.well-known/morrow-proof-keys.json``; the ZIP
carries a short verifier.

The proposed addendum is reviewed data (``data/vendor_addendum.json``, with its version and date):
a plain-English clause template that always carries its "Template, not legal advice" notice and
makes no claim about what any law requires. Its target date is the buyer's choice, defaulted from
the deadline.

Tickets need no credentials and make no calls: a GitHub "new issue" link (title and body in the URL,
kept within GitHub's URL length), a Jira-importable CSV and a Markdown ticket to copy.

Morrow sends nothing to anyone: every output here is a file or text for the buyer.
An opted-out domain never appears, in a pack, a ticket or the all-vendors ZIP.
"""

from __future__ import annotations

import csv
import hashlib
import html
import io
import json
import os
import re
import zipfile
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

from db_feature_store import feature_conn

EVIDENCE_FORMAT = "morrow.vendor-evidence/v1"
ENVELOPE_FORMAT = "morrow.vendor-evidence-envelope/v1"
#: Every evidence signature is over this prefix followed by the canonical document.
EVIDENCE_CONTEXT = b"morrow.vendor-evidence.v1\n"
ADDENDUM_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data",
                             "vendor_addendum.json")
METHOD_URL = "https://github.com/soqlab/Morrow/blob/main/docs/PUBLIC_GRADE.md"
MAX_CHECKS = 5
MAX_OBSERVATIONS = 5
#: When the deadline has already passed, the proposed target date is this far from today.
PASSED_DEADLINE_DAYS = 180
#: GitHub answers 414 for very long URLs; a prefilled "new issue" link stays under this.
GITHUB_URL_MAX = 8000
_REPO_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
#: A rendered addendum is checked for these words: a template must never claim a legal requirement.
LEGAL_CLAIMS = ("required by law", "law requires", "legally required", "mandated by", "regulation requires")

_addendum_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}


class EvidenceError(Exception):
    def __init__(self, status_code: int, error: str, detail: str):
        super().__init__(detail)
        self.status_code = int(status_code)
        self.error = str(error)
        self.detail = str(detail)

    def as_dict(self) -> Dict[str, Any]:
        return {"error": self.error, "detail": self.detail}


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _utc(text: Any) -> str:
    """A stored timestamp as ``YYYY-MM-DDTHH:MM:SSZ`` (UTC), or "" when it cannot be read."""
    raw = str(text or "").strip()
    if not raw:
        return ""
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00").replace(" ", "T"))
    except ValueError:
        return ""
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return _iso(parsed.replace(microsecond=0))


def _human(stamp: str) -> str:
    """``2026-11-19T08:04:00Z`` -> ``2026-11-19 08:04 UTC``."""
    return (stamp[:10] + " " + stamp[11:16] + " UTC") if len(stamp) >= 16 else stamp


# ── The addendum (reviewed data) ─────────────────────────────────────────────


def addendum_template() -> Dict[str, Any]:
    path = ADDENDUM_PATH
    mtime = os.path.getmtime(path)
    cached = _addendum_cache.get(path)
    if cached and cached[0] == mtime:
        return cached[1]
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    for key in ("format", "version", "date", "title", "notice", "intro", "clauses", "sources"):
        if not data.get(key):
            raise ValueError(f"data/vendor_addendum.json has no {key}")
    if "not legal advice" not in data["notice"].lower():
        raise ValueError("data/vendor_addendum.json must say it is not legal advice")
    _addendum_cache[path] = (mtime, data)
    return data


def _fill(text: str, values: Dict[str, str]) -> str:
    return re.sub(r"\{(\w+)\}", lambda m: values.get(m.group(1), m.group(0)), text)


def addendum_markdown(domains: List[str], target_date: str, base_url: str, vendor: str = "") -> str:
    """The proposed addendum for these endpoints, as Markdown. The notice comes first and last."""
    t = addendum_template()
    ph = t.get("placeholders") or {}
    values = {
        "buyer": ph.get("buyer", "[Your company]"),
        "vendor": vendor or ph.get("vendor", "[Vendor]"),
        "agreement": ph.get("agreement", "[the agreement]"),
        "endpoints": ", ".join(domains),
        "date": _long_date(target_date),
        "check_url": (base_url.rstrip("/") or "https://morrow.soqlab.com") + "/" + (domains[0] if domains else ""),
    }
    lines = [f"# {t['title']}", "", f"> **{t['notice']}**", "",
             f"Template version {t['version']}, {t['date']}.", "", _fill(t["intro"], values), ""]
    for number, clause in enumerate(t["clauses"], 1):
        lines += [f"## {number}. {clause['heading']}", "", _fill(clause["text"], values), ""]
    lines += ["## Sources", ""]
    lines += [f"- {s['label']}: {s['url']}" for s in t["sources"]]
    lines += ["", "---", "", f"*{t['notice']}* {t.get('review') or ''}".rstrip(), ""]
    return "\n".join(lines)


def _long_date(value: str) -> str:
    try:
        d = date.fromisoformat(value)
    except ValueError:
        return value
    return f"{d.day} {d.strftime('%B')} {d.year}"


# ── The deadline (the board slide's logic) ───────────────────────────────────


def deadline_for(data: Any, now: Optional[datetime] = None) -> Dict[str, Any]:
    """The deadline for one vendor that is not quantum-safe, for the buyer's kind of data.

    Exactly services/board_slide._deadline with no inventory and one endpoint at risk, plus the
    sentence and the sources the slide prints.
    """
    from services import board_slide, decrypt_window, risk_sentence, shelf_life

    now = now or _now()
    out = board_slide._deadline(None, [], data, None, {"safe": 0, "at_risk": 1, "unknown": 0}, now)
    shelf = risk_sentence._data(data, None, "")
    sources = [f"Quantum year: estimate {out['crqc_low']} to {out['crqc_likely']}, "
               f"{decrypt_window.EXPOSURE_SOURCE_LABEL} (published March 2026), {decrypt_window.EXPOSURE_SOURCE_URL}"]
    basis = out.get("basis")
    if basis and basis.get("kind") == "shelf_life":
        payload = shelf_life.public_payload()
        sources.append(f"{basis['text']}, dated {payload.get('date') or 'undated'}, "
                       f"{(payload.get('attribution') or {}).get('source_url') or ''}".rstrip(", "))
    else:
        sources.append("Data lifetime: not measured yet")
    value = str(out.get("value") or "")
    sentence = f"Must be quantum-safe by: {value}" + (f" ({out['range']})" if out.get("range") else "") + ". " + out["label"]
    kind = None
    if shelf is not None:
        kind = {"category": shelf["category"], "label": shelf["label"], "assumed": bool(shelf["assumed"]),
                "years": int(shelf["years"]), "jurisdiction": shelf["jurisdiction"], "edition": shelf["edition"]}
    return {"status": out["status"], "value": value, "range": out.get("range"), "label": out["label"],
            "sentence": sentence, "is_estimate": True, "years": out.get("years"),
            "safe_by_low": out.get("safe_by_low"), "safe_by_likely": out.get("safe_by_likely"),
            "secret_until": out.get("secret_until"), "crqc_low": out["crqc_low"], "crqc_likely": out["crqc_likely"],
            "kind_of_data": kind, "basis": (basis or {}).get("text"), "sources": sources}


def default_target_date(deadline: Dict[str, Any], now: Optional[datetime] = None) -> Tuple[str, str]:
    """(YYYY-MM-DD, why) for the addendum's target date, from the deadline."""
    now = now or _now()
    low = deadline.get("safe_by_low")
    if deadline.get("status") == "ahead" and isinstance(low, int) and low > now.year:
        return f"{low}-01-01", (f"1 January {low}: data of this kind sent over a classical key exchange after about "
                                f"{low} could still need to be private when a quantum computer could read it.")
    day = (now + timedelta(days=PASSED_DEADLINE_DAYS)).date().isoformat()
    return day, (f"{PASSED_DEADLINE_DAYS} days from today: for this kind of data the deadline has already passed, "
                 "so the proposed date leaves the vendor a working window. Change it to suit you.")


def target_date(by: Any, deadline: Dict[str, Any], now: Optional[datetime] = None) -> Tuple[str, str, bool]:
    """(date, why, chosen): the buyer's date when given and valid, else the default."""
    now = now or _now()
    text = str(by or "").strip()
    if not text:
        day, why = default_target_date(deadline, now)
        return day, why, False
    if not _DATE_RE.match(text):
        raise EvidenceError(400, "bad_date", "Give the target date as YYYY-MM-DD.")
    try:
        chosen = date.fromisoformat(text)
    except ValueError:
        raise EvidenceError(400, "bad_date", "That target date is not a real date.") from None
    if chosen < now.date() or chosen > now.date() + timedelta(days=366 * 20):
        raise EvidenceError(400, "bad_date", "Choose a target date from today up to 20 years ahead.")
    return text, "Chosen by you.", True


# ── What Morrow measured ─────────────────────────────────────────────────────


def grade_checks(domain: str, limit: int = MAX_CHECKS) -> List[Dict[str, Any]]:
    """The stored public grade checks of domain, newest first, as evidence rows (measured only)."""
    from services import public_grade

    public_grade.init_tables()
    with feature_conn() as conn:
        rows = conn.execute(
            "SELECT id, scanned_at, grade, key_exchange_group, post_quantum, rubric_version, result_json "
            "FROM public_grade_checks WHERE domain = ? ORDER BY scanned_at DESC, id DESC LIMIT ?",
            (domain, max(1, min(50, int(limit))))).fetchall()
    out = []
    for r in rows:
        try:
            result = json.loads(r["result_json"])
        except (TypeError, ValueError):
            result = {}
        versions = (result.get("tls") or {}).get("versions") or {}
        untested = list((result.get("tls") or {}).get("untested") or [])
        cert = result.get("certificate") or {}
        out.append({
            "check_id": int(r["id"]),
            "checked_at": _utc(r["scanned_at"]),
            "grade": str(r["grade"] or ""),
            "rubric_version": str(r["rubric_version"] or result.get("rubric_version") or ""),
            "key_exchange_group": str(r["key_exchange_group"] or "") or None,
            "post_quantum_key_exchange": bool(r["post_quantum"]),
            "tls_versions_accepted": sorted(str(v) for v, on in versions.items() if on is True),
            "tls_versions_refused": sorted(str(v) for v, on in versions.items() if on is False),
            "tls_versions_untested": sorted(str(v) for v in untested),
            "certificate_verified": bool(cert.get("verified")) if "verified" in cert else None,
            "_result": result,
        })
    return out


def registry_observations(domain: str, base_url: str, limit: int = MAX_OBSERVATIONS) -> List[Dict[str, Any]]:
    """The registry's dated observations of domain, newest first, each with its permalink.

    Empty for a hidden (opted-out) or never-observed domain: registry_history hides them.
    """
    from services import public_check

    out = []
    for row in public_check.registry_history(domain, limit):
        obs = public_check.registry_observation(domain, int(row["observation_id"]))
        if obs is None:
            continue
        observed = (obs.get("result") or {}).get("observed") or {}
        oid = int(obs["observation_id"])
        out.append({
            "observation_id": oid,
            "permalink": f"{base_url}/r/{domain}/at/{oid}",
            "observed_at": _utc(obs.get("observed_at")),
            "last_seen_at": _utc(obs.get("last_seen_at")),
            "reachable": bool(observed.get("reachable")),
            "tls_version_negotiated": str(observed.get("tls_version") or "") or None,
            "key_exchange_group": (str(observed.get("key_exchange") or "") or None)
            if observed.get("key_exchange_observed") else None,
            "certificate_verified": bool(observed.get("certificate_verified")) if observed.get("reachable") else None,
            "posture": str(obs.get("posture") or ""),
        })
    return out


# ── The pack ─────────────────────────────────────────────────────────────────


def _clean(check: Dict[str, Any], domain: str, base_url: str) -> Dict[str, Any]:
    row = {k: v for k, v in check.items() if not k.startswith("_")}
    row["history_url"] = f"{base_url}/api/public/history/{domain}?detail=1"
    return row


def build_document(domain: str, checks: List[Dict[str, Any]], observations: List[Dict[str, Any]],
                   deadline: Dict[str, Any], target: Tuple[str, str, bool], addendum_sha256: str,
                   base_url: str, keys: List[Dict[str, Any]], issued_at: str) -> Dict[str, Any]:
    """The evidence document. Pure: only what is passed in, which is only what Morrow measured."""
    from services import proof_signing, vendor_check

    newest = checks[0]
    entry = vendor_check._entry_from_result(domain, newest["_result"] or {"grade": newest["grade"]})
    entry["key_exchange"] = newest["key_exchange_group"]
    t = addendum_template()
    return {
        "format": EVIDENCE_FORMAT,
        "domain": domain,
        "status": "not_quantum_safe",
        "statement": (f"On {_human(newest['checked_at'])}, Morrow's public check of {domain} "
                      f"{vendor_check._fact(entry)} (grade {newest['grade']}, rubric {newest['rubric_version']})."),
        "what_decides_it": entry.get("why") or "",
        "grade_checks": [_clean(c, domain, base_url) for c in checks],
        "registry_observations": observations,
        "registry_record": f"{base_url}/r/{domain}" if observations else None,
        "deadline": deadline,
        "proposed_target_date": {"date": target[0], "why": target[1], "chosen_by_buyer": bool(target[2])},
        "addendum": {"id": t.get("id") or "", "version": t["version"], "date": t["date"],
                     "notice": t["notice"], "sha256": addendum_sha256},
        "method": {
            "text": ("Morrow's public grade: one set of read-only TLS handshakes to port 443 of the domain, offering "
                     "post-quantum key-exchange groups and recording which group the server chose, which TLS "
                     "versions it accepted and whether its certificate verified. One public endpoint at the "
                     "moments listed; not an audit of anything behind it."),
            "rubric_version": newest["rubric_version"],
            "about_scanner": f"{base_url}/about-scanner",
            "method_url": METHOD_URL,
        },
        "issued_at": issued_at,
        "issuer": {"product": "Morrow", "keys_url": base_url + proof_signing.WELL_KNOWN_PATH},
        "signing_context": EVIDENCE_CONTEXT.decode("ascii").strip(),
        "signing_keys": [proof_signing.public_descriptor(k) for k in keys],
        "sends_nothing": "Morrow sends nothing to the vendor. This pack is for the buyer to send, if they choose.",
    }


def sign(doc: Dict[str, Any], keys: List[Dict[str, Any]]) -> Dict[str, Any]:
    from services import proof_signing

    message = proof_signing.canonical_bytes(doc)
    signatures = proof_signing.sign(message, keys, context=EVIDENCE_CONTEXT)
    by_kid = {k["kid"]: k for k in keys}
    for sig in signatures:  # never hand out a pack this server cannot itself verify
        if not proof_signing.verify_signature(sig["alg"], by_kid[sig["kid"]]["public_key_b64"], sig["signature"],
                                              message, context=EVIDENCE_CONTEXT):
            raise EvidenceError(500, "self_check_failed", "The pack's signature did not verify on this server.")
    return {"format": ENVELOPE_FORMAT, "document": doc, "signatures": signatures}


def verify(envelope: Dict[str, Any], published: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Check an evidence envelope's signatures against the published keys, under the evidence context."""
    from services import proof_signing

    published = published or proof_signing.published_keys()
    keys = {k["kid"]: k for k in published.get("keys") or []}
    doc = envelope.get("document") or {}
    message = proof_signing.canonical_bytes(doc)
    checks = []
    for sig in envelope.get("signatures") or []:
        key = keys.get(sig.get("kid"))
        ok = bool(key) and key.get("alg") == sig.get("alg") and proof_signing.verify_signature(
            sig.get("alg"), key["public_key"], sig.get("signature") or "", message, context=EVIDENCE_CONTEXT)
        checks.append({"kid": sig.get("kid"), "alg": sig.get("alg"), "ok": ok})
    valid = bool(checks) and all(c["ok"] for c in checks) and doc.get("format") == EVIDENCE_FORMAT
    return {"valid": valid, "checks": checks}


def _keys() -> List[Dict[str, Any]]:
    from services import proof_signing

    try:
        keys = proof_signing.active_key_set(create=True)
    except proof_signing.SigningUnavailable as exc:
        raise EvidenceError(503, "signing_unavailable", f"This server cannot sign evidence packs: {exc}") from None
    if not keys:
        raise EvidenceError(503, "signing_unavailable", "This server has no signing key.")
    return keys


def _vendor_entry(report: Dict[str, Any], domain: str) -> Dict[str, Any]:
    from services import public_check

    host = str(domain or "").strip().lower().rstrip(".")
    entry = next((v for v in report.get("vendors") or [] if v.get("domain") == host), None)
    # An opted-out domain is answered exactly like one that is not in the report.
    if entry is None or public_check.opted_out(host):
        raise EvidenceError(404, "not_found", "That vendor is not in this report.")
    if entry.get("grade") is None:
        raise EvidenceError(409, "not_graded", f"{host} has not been graded yet, so there is no evidence to pack.")
    if not entry.get("exposed"):
        raise EvidenceError(409, "quantum_safe", f"{host} already uses post-quantum key exchange; there is nothing to ask for.")
    return entry


def needs_pack(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The report's vendors that get a pack: graded, below B, not opted out. Worst first, as in the report."""
    from services import public_check

    return [v for v in report.get("vendors") or []
            if v.get("grade") is not None and v.get("exposed") and not public_check.opted_out(v["domain"])]


def make_pack(report: Dict[str, Any], domain: str, base_url: str, data: Any = None, by: Any = None,
              keys: Optional[List[Dict[str, Any]]] = None, now: Optional[datetime] = None) -> Dict[str, Any]:
    """Everything for one vendor: the signed envelope and the texts that go with it."""
    from services import vendor_check

    base = base_url.rstrip("/")
    now = now or _now()
    entry = _vendor_entry(report, domain)
    host = entry["domain"]
    checks = grade_checks(host)
    if not checks:
        raise EvidenceError(409, "not_graded", f"There is no stored check of {host} to pack.")
    if checks[0]["grade"] in vendor_check.READY:
        raise EvidenceError(409, "quantum_safe", f"The newest check of {host} ({_human(checks[0]['checked_at'])}) "
                            "saw post-quantum key exchange; there is nothing to ask for.")
    deadline = deadline_for(data, now)
    target = target_date(by, deadline, now)
    addendum = addendum_markdown([host], target[0], base)
    keys = keys if keys is not None else _keys()
    doc = build_document(host, checks, registry_observations(host, base), deadline, target,
                         hashlib.sha256(addendum.encode("utf-8")).hexdigest(), base, keys, _iso(now))
    envelope = sign(doc, keys)
    note_entry = dict(entry)
    note_entry.update(key_exchange=checks[0]["key_exchange_group"], checked_at=checks[0]["checked_at"],
                      grade=checks[0]["grade"], why=doc["what_decides_it"])
    note = vendor_check.note(note_entry, base)
    title, body = ticket(doc)
    return {"domain": host, "envelope": envelope, "addendum_md": addendum, "note": note,
            "ticket_title": title, "ticket_md": f"# {title}\n\n{body}\n", "ticket_body": body}


# ── Tickets ──────────────────────────────────────────────────────────────────


def ticket(doc: Dict[str, Any]) -> Tuple[str, str]:
    """(title, Markdown body) for a ticket about one vendor."""
    d = doc["domain"]
    newest = doc["grade_checks"][0]
    dl = doc["deadline"]
    title = f"Ask {d} for post-quantum key exchange (X25519MLKEM768) by {doc['proposed_target_date']['date']}"
    lines = [
        f"**What Morrow saw:** {doc['statement']}",
        "",
        f"**Deadline:** {dl['sentence']}",
        "",
        "**Evidence:**",
        f"- Check {newest['check_id']} on {_human(newest['checked_at'])}: key exchange "
        f"{newest['key_exchange_group'] or 'not observed'}, TLS {', '.join(newest['tls_versions_accepted']) or 'none'} accepted, "
        f"certificate {'verified' if newest['certificate_verified'] else 'did not verify'}; history: {newest['history_url']}",
    ]
    for obs in doc["registry_observations"][:3]:
        lines.append(f"- Registry observation {obs['observation_id']} on {_human(obs['observed_at'])}: {obs['permalink']}")
    lines += [
        "",
        "**To do:**",
        f"- [ ] Send {d} the note in the evidence pack (ask-your-vendor.txt).",
        f"- [ ] Propose the addendum (addendum.md) with target date {doc['proposed_target_date']['date']}. "
        f"{doc['addendum']['notice']}",
        f"- [ ] Re-check {d} on or after the target date: {doc['method']['about_scanner'].rsplit('/', 1)[0]}/{d}",
        "",
        f"Signed evidence: Morrow vendor evidence pack, issued {_human(doc['issued_at'])}; keys: {doc['issuer']['keys_url']}",
    ]
    return title, "\n".join(lines)


def github_issue_url(repo: str, title: str, body: str) -> str:
    """A prefilled GitHub "new issue" link, kept under GITHUB_URL_MAX characters. No call is made."""
    repo = str(repo or "").strip().strip("/")
    if repo.startswith("https://github.com/"):
        repo = repo[len("https://github.com/"):].strip("/")
    if not _REPO_RE.match(repo):
        raise EvidenceError(400, "bad_repo", "Give the GitHub repository as owner/name, for example acme/security.")
    base = f"https://github.com/{repo}/issues/new?title={quote(title[:250], safe='')}&labels=post-quantum&body="
    tail = "\n\n(Shortened to fit a link. The full text is ticket.md in the evidence pack.)"
    text = body
    url = base + quote(text, safe="")
    if len(url) <= GITHUB_URL_MAX:
        return url
    room = GITHUB_URL_MAX - len(base) - len(quote(tail, safe=""))
    lo, hi = 0, len(text)
    while lo < hi:  # the longest prefix whose encoding fits
        mid = (lo + hi + 1) // 2
        if len(quote(text[:mid], safe="")) <= room:
            lo = mid
        else:
            hi = mid - 1
    return base + quote(text[:lo] + tail, safe="")


def _cell(value: Any) -> str:
    text = str(value if value is not None else "")
    # A cell that starts with =, +, -, @ (or a tab / carriage return) is a formula to a spreadsheet.
    return ("'" + text) if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def jira_csv(packs: List[Dict[str, Any]]) -> str:
    """One Jira-importable row per vendor (File > Import issues from CSV; date format yyyy-MM-dd)."""
    out = io.StringIO()
    w = csv.writer(out, lineterminator="\r\n", quoting=csv.QUOTE_ALL)
    w.writerow(["Summary", "Description", "Issue Type", "Labels", "Due Date"])
    for p in packs:
        doc = p["envelope"]["document"]
        w.writerow([_cell(p["ticket_title"]), _cell(p["ticket_body"]), "Task", "post-quantum",
                    _cell(doc["proposed_target_date"]["date"])])
    return out.getvalue()


# ── The printable page ───────────────────────────────────────────────────────

_HTML_STYLE = """
:root{--bg:#fbfcfb;--ink:#111614;--ink2:#3d4642;--ink3:#5e6863;--rule:#d5dad7;--panel:#ffffff;--warn:#8a4b00;--ok:#2f6b1f;--accent:#b9f26b}
@media (prefers-color-scheme:dark){:root{--bg:#0e1211;--ink:#e8ece9;--ink2:#c3cac6;--ink3:#97a19c;--rule:#2b3330;--panel:#151a18;--warn:#f0b35a;--ok:#9fd977}}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:860px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:clamp(24px,4vw,34px);line-height:1.15;margin:0 0 6px}h2{font-size:19px;margin:32px 0 8px;padding-top:12px;border-top:1px solid var(--rule)}
p{margin:0 0 10px}.lede{font-size:18px;color:var(--ink2)}.fine{font-size:13px;color:var(--ink3)}
.seal{display:inline-flex;align-items:center;gap:8px;border:1px solid var(--rule);border-radius:999px;padding:4px 12px;font-size:13px;color:var(--ink2);background:var(--panel)}
.seal b{color:var(--ok)}.warn{color:var(--warn)}.notice{border:2px solid var(--warn);border-radius:8px;padding:10px 14px;font-weight:600;background:var(--panel)}
.wrap{overflow-x:auto;border:1px solid var(--rule);border-radius:8px;background:var(--panel)}
table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--rule);vertical-align:top}
th{font-weight:600;color:var(--ink2);white-space:nowrap}tr:last-child td{border-bottom:0}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px;overflow-wrap:anywhere}
a{color:inherit}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:var(--panel);border:1px solid var(--rule);border-radius:8px;padding:12px;font-size:13px}
.addendum h3{font-size:16px;margin:16px 0 4px}
@media print{:root{--bg:#fff;--ink:#000;--ink2:#222;--ink3:#444;--rule:#bbb;--panel:#fff}main{padding:0}a{text-decoration:none}h2{break-after:avoid}table,pre,.notice{break-inside:avoid}}
"""


def _e(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def _link(url: Any, text: Any = None) -> str:
    u = str(url or "")
    if not u.startswith(("https://", "http://", "/")):
        return _e(text if text is not None else u)
    return f'<a href="{_e(u)}">{_e(text if text is not None else u)}</a>'


def render_html(pack: Dict[str, Any]) -> str:
    """The printable evidence page: self-contained (no script, nothing from another origin), both themes."""
    env = pack["envelope"]
    doc = env["document"]
    dl = doc["deadline"]
    rows = "".join(
        f"<tr><td class=mono>{_e(_human(c['checked_at']))}</td><td class=mono>{_e(c['check_id'])}</td>"
        f"<td><b>{_e(c['grade'])}</b> <span class=fine>rubric {_e(c['rubric_version'])}</span></td>"
        f"<td class=mono>{_e(c['key_exchange_group'] or 'not observed')}</td>"
        f"<td class=mono>{_e(', '.join(c['tls_versions_accepted']) or 'none')}</td>"
        f"<td>{'yes' if c['certificate_verified'] else ('no' if c['certificate_verified'] is False else 'not read')}</td></tr>"
        for c in doc["grade_checks"])
    obs = "".join(
        f"<tr><td class=mono>{_e(_human(o['observed_at']))}</td><td>{_link(o['permalink'], o['observation_id'])}</td>"
        f"<td class=mono>{_e(o['key_exchange_group'] or 'not observed')}</td><td class=mono>{_e(o['tls_version_negotiated'] or '-')}</td>"
        f"<td>{'yes' if o['certificate_verified'] else ('no' if o['certificate_verified'] is False else '-')}</td></tr>"
        for o in doc["registry_observations"])
    sigs = "".join(f"<tr><td>{_e(s['alg'])}</td><td class=mono>{_e(s['kid'])}</td><td class=mono>{_e(s['signature'][:48])}…</td></tr>"
                   for s in env["signatures"])
    add_html = _markdown_to_html(pack["addendum_md"])
    kind = dl.get("kind_of_data") or {}
    kind_text = (f"{kind.get('label')}, {'assumed (you chose Not sure)' if kind.get('assumed') else 'your choice'}"
                 if kind else "not known")
    t = doc["proposed_target_date"]
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>Evidence pack: {_e(doc['domain'])}</title><style>{_HTML_STYLE}</style></head>
<body><main>
<p class="seal" role="note"><b aria-hidden="true">&#10003;</b> Signed by Morrow, Ed25519 and ML-DSA-65, {_e(_human(doc['issued_at']))}</p>
<h1>Evidence pack: {_e(doc['domain'])}</h1>
<p class="lede">{_e(doc['statement'])}</p>
<p><span class="warn">{_e(dl['sentence'])}</span></p>
<p class="fine">Kind of data: {_e(kind_text)}. Estimate; sources below.</p>

<h2>What Morrow measured</h2>
<p class="fine">Public grade checks of {_e(doc['domain'])}, newest first. Times are UTC.</p>
<div class="wrap"><table><thead><tr><th scope="col">Checked</th><th scope="col">Check id</th><th scope="col">Grade</th><th scope="col">Key exchange chosen</th><th scope="col">TLS accepted</th><th scope="col">Certificate verified</th></tr></thead><tbody>{rows}</tbody></table></div>
<p class="fine">All checks: {_link(doc['grade_checks'][0]['history_url'])}</p>
{('<h2>Registry observations</h2><p class="fine">Dated, citable observations from the public record, newest first.</p><div class="wrap"><table><thead><tr><th scope="col">Observed</th><th scope="col">Permalink</th><th scope="col">Key exchange</th><th scope="col">TLS negotiated</th><th scope="col">Certificate verified</th></tr></thead><tbody>' + obs + '</tbody></table></div>') if obs else '<h2>Registry observations</h2><p class="fine">The public record has no dated observation of this domain yet; the grade checks above are the evidence.</p>'}

<h2>The deadline</h2>
<p>{_e(dl['label'])}</p>
<ul class="fine">{''.join('<li>' + _e(s) + '</li>' for s in dl['sources'])}</ul>

<h2>Proposed addendum</h2>
<p class="notice">{_e(doc['addendum']['notice'])}</p>
<p class="fine">Target date {_e(t['date'])}: {_e(t['why'])}</p>
<div class="addendum">{add_html}</div>

<h2>How Morrow measures</h2>
<p>{_e(doc['method']['text'])}</p>
<p class="fine">What the checker connects to and how to opt out: {_link(doc['method']['about_scanner'])}. The grading rubric ({_e(doc['method']['rubric_version'])}): {_link(doc['method']['method_url'])}.</p>

<h2>Signatures</h2>
<p class="fine">The signed document is evidence.json in this pack. Each signature is over the context <code>{_e(doc['signing_context'])}</code> and a newline, followed by the canonical JSON of the document (sorted keys, no spaces, UTF-8). Check them with verify.py in this pack against the published keys: {_link(doc['issuer']['keys_url'])}.</p>
<div class="wrap"><table><thead><tr><th scope="col">Algorithm</th><th scope="col">Key id</th><th scope="col">Signature</th></tr></thead><tbody>{sigs}</tbody></table></div>
<p class="fine">{_e(doc['sends_nothing'])}</p>
</main></body></html>
"""


def _markdown_to_html(md: str) -> str:
    """The small Markdown the addendum uses: headings, a quote, bullets, rules, bold and italics."""
    out: List[str] = []
    in_list = False
    for line in md.splitlines():
        if in_list and not line.startswith("- "):
            out.append("</ul>")
            in_list = False
        text = _e(line)
        text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
        text = re.sub(r"(?<!\*)\*(?!\s)(.+?)\*", r"<i>\1</i>", text)
        if line.startswith("# "):
            continue  # the page has its own heading
        if line.startswith("## "):
            out.append(f"<h3>{text[3:]}</h3>")
        elif line.startswith("&gt; "):
            continue  # the notice is shown above, in its own box
        elif line.startswith("> "):
            continue
        elif line.startswith("- "):
            if not in_list:
                out.append("<ul class=fine>")
                in_list = True
            out.append(f"<li>{text[2:]}</li>")
        elif line.strip() == "---":
            out.append("<hr>")
        elif line.strip():
            out.append(f"<p>{text}</p>")
    if in_list:
        out.append("</ul>")
    return "\n".join(out)


# ── The ZIP ──────────────────────────────────────────────────────────────────

VERIFY_PY = '''#!/usr/bin/env python3
"""Check a Morrow vendor evidence pack offline.

    python verify.py evidence.json evidence.signatures.json morrow-proof-keys.json

Get morrow-proof-keys.json from the issuer's keys_url (in evidence.json) through a channel you trust,
or compare it with the copy in this pack. Needs: pip install cryptography (ML-DSA-65 needs
cryptography >= 47 built with OpenSSL >= 3.5). Exit 0 when every signature verifies.
"""
import base64, json, sys

CONTEXT = b"morrow.vendor-evidence.v1\\n"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def main(doc_path, sigs_path, keys_path):
    doc = json.load(open(doc_path, encoding="utf-8"))
    sigs = json.load(open(sigs_path, encoding="utf-8"))
    keys = {k["kid"]: k for k in json.load(open(keys_path, encoding="utf-8")).get("keys", [])}
    message = CONTEXT + canonical(doc)
    ok = doc.get("format") == "morrow.vendor-evidence/v1" and bool(sigs.get("signatures"))
    for sig in sigs.get("signatures", []):
        key = keys.get(sig["kid"])
        good = False
        try:
            pub, raw = base64.b64decode(key["public_key"]), base64.b64decode(sig["signature"])
            if sig["alg"] == "Ed25519":
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
                Ed25519PublicKey.from_public_bytes(pub).verify(raw, message)
                good = True
            elif sig["alg"] == "ML-DSA-65":
                from cryptography.hazmat.primitives.asymmetric import mldsa
                mldsa.MLDSA65PublicKey.from_public_bytes(pub).verify(raw, message)
                good = True
        except Exception:
            good = False
        print(("ok      " if good else "FAILED  ") + sig["alg"] + "  " + sig["kid"])
        ok = ok and good
    print("verified" if ok else "NOT verified")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:4]))
'''


def _readme(domains: List[str], keys_url: str) -> str:
    who = domains[0] if len(domains) == 1 else f"{len(domains)} vendors"
    return "\r\n".join([
        f"Morrow vendor evidence pack: {who}",
        "",
        "evidence.json             what Morrow measured, signed (the signed document)",
        "evidence.signatures.json  its Ed25519 and ML-DSA-65 signatures",
        "evidence.html             the same, printable: open it in a browser, print or save as PDF",
        "addendum.md               a proposed contract addendum. Template, not legal advice: have your lawyer review it.",
        "ask-your-vendor.txt       a short note you can send the vendor",
        "ticket.md                 a ready-made ticket to paste into your tracker",
        "jira.csv                  the same as a Jira import (Import issues from CSV; date format yyyy-MM-dd)",
        "morrow-proof-keys.json    the published signing keys when this pack was made",
        "verify.py                 checks the signatures offline: python verify.py evidence.json evidence.signatures.json morrow-proof-keys.json",
        "",
        f"Compare morrow-proof-keys.json with {keys_url} before you rely on it.",
        "Morrow sends nothing to your vendors. Everything here is for you to send, if you choose.",
        "",
    ])


def _signatures_file(env: Dict[str, Any]) -> Dict[str, Any]:
    from services import proof_signing

    doc = env["document"]
    return {"format": ENVELOPE_FORMAT, "signing_context": doc["signing_context"],
            "document_sha256": hashlib.sha256(proof_signing.canonical_bytes(doc)).hexdigest(),
            "keys_url": doc["issuer"]["keys_url"], "signatures": env["signatures"]}


FILE_NAMES = ("evidence.json", "evidence.signatures.json", "evidence.html", "addendum.md", "ask-your-vendor.txt",
              "ticket.md", "jira.csv", "morrow-proof-keys.json", "verify.py", "README.txt")


def pack_files(pack: Dict[str, Any], published: Dict[str, Any]) -> List[Tuple[str, bytes]]:
    """The files of one vendor's pack, in order."""
    env = pack["envelope"]
    doc = env["document"]

    def j(value: Any) -> bytes:
        return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")

    return [
        ("evidence.json", j(doc)),
        ("evidence.signatures.json", j(_signatures_file(env))),
        ("evidence.html", render_html(pack).encode("utf-8")),
        ("addendum.md", pack["addendum_md"].encode("utf-8")),
        ("ask-your-vendor.txt", pack["note"].replace("\n", "\r\n").encode("utf-8")),
        ("ticket.md", pack["ticket_md"].encode("utf-8")),
        ("jira.csv", jira_csv([pack]).encode("utf-8")),
        ("morrow-proof-keys.json", j(published)),
        ("verify.py", VERIFY_PY.encode("utf-8")),
        ("README.txt", _readme([pack["domain"]], doc["issuer"]["keys_url"]).encode("utf-8")),
    ]


def _zip(entries: List[Tuple[str, bytes]], when: datetime) -> bytes:
    buf = io.BytesIO()
    stamp = (max(1980, when.year), when.month, when.day, when.hour, when.minute, when.second)
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries:
            info = zipfile.ZipInfo(name, date_time=stamp)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, data)
    return buf.getvalue()


def zip_one(pack: Dict[str, Any], published: Optional[Dict[str, Any]] = None,
            now: Optional[datetime] = None) -> bytes:
    from services import proof_signing

    return _zip(pack_files(pack, published or proof_signing.published_keys()), now or _now())


def zip_all(packs: List[Dict[str, Any]], published: Optional[Dict[str, Any]] = None,
            now: Optional[datetime] = None) -> bytes:
    """Every vendor's pack in its own folder, with one Jira CSV for all of them at the top."""
    from services import proof_signing

    published = published or proof_signing.published_keys()
    entries: List[Tuple[str, bytes]] = []
    for p in packs:
        entries += [(f"{p['domain']}/{name}", data) for name, data in pack_files(p, published)]
    keys_url = packs[0]["envelope"]["document"]["issuer"]["keys_url"] if packs else proof_signing.WELL_KNOWN_PATH
    entries.append(("jira.csv", jira_csv(packs).encode("utf-8")))
    entries.append(("README.txt", (_readme([p["domain"] for p in packs] or ["no vendors"], keys_url)
                                   + "One folder per vendor, worst first as in your report; jira.csv at the top has one row per vendor.\r\n").encode("utf-8")))
    return _zip(entries, now or _now())


def all_packs(report: Dict[str, Any], base_url: str, data: Any = None, by: Any = None,
              now: Optional[datetime] = None) -> Dict[str, Any]:
    """A pack for every vendor that needs one; the ones that could not be packed, with why."""
    now = now or _now()
    keys = _keys()
    packs, skipped = [], []
    for v in needs_pack(report):
        try:
            packs.append(make_pack(report, v["domain"], base_url, data, by, keys=keys, now=now))
        except EvidenceError as exc:
            if exc.status_code in (400, 503):
                raise
            skipped.append({"domain": v["domain"], "reason": exc.detail})
    return {"packs": packs, "skipped": skipped}


def filename(domain: Optional[str], now: Optional[datetime] = None, count: int = 0) -> str:
    day = (now or _now()).strftime("%Y-%m-%d")
    if domain:
        return f"morrow-evidence-{domain}-{day}.zip"
    return f"morrow-evidence-{count}-vendor{'s' if count != 1 else ''}-{day}.zip"
