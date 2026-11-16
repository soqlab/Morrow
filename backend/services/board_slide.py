"""Board slide in one click: one 16:9 slide for a board pack, as PPTX and PDF.

The slide answers four questions with what Morrow already measures, and nothing else:

  * the risk, in one sentence: services/risk_sentence.build over the organization's newest scan of
    each endpoint (the same words as the console's scan results and the public check);
  * the deadline: by when the most sensitive data in scope must be quantum-safe. Mosca's
    inequality on the harvest clock (services/decrypt_window): a secret that must stay private for
    x years is safe only if it is sent over a quantum-safe key exchange at least x years before a
    quantum computer can read it, so the deadline is the Global Risk Institute's estimate (2035 to
    2040) minus x. x is the longest of the Shelf-Life entry the sentence uses and any numeric
    confidentiality lifetime on an asset in the inventory. It is an estimate and always says so,
    with its range;
  * the trend: the most honest series there is. First the measured share of scanned endpoints with
    a quantum-safe key exchange at the end of each month (each endpoint's newest scan by then);
    without two months of scans, the fire drill's estimated time-to-safe (services/fire_drill.py),
    labelled as an estimate with its range; otherwise "not measured yet";
  * one to three next actions, from the fix queue (/fix-next) and the endpoints' own state.

Every figure carries its source and date in the footer. Missing data is said, never filled in.

``build`` is pure. ``gather`` reads the current tenant's data (db's organization context, which the
request middleware sets). ``render_pptx`` writes the OOXML package by hand with the standard
library: one slide, editable text boxes, the chart drawn as shapes, no images; no extra
dependency. ``render_pdf`` uses reportlab, which the PDF compliance export already depends on.
"""

from __future__ import annotations

import io
import math
import re
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from xml.sax.saxutils import escape as _xml_escape

from services import crypto_switch, decrypt_window, risk_sentence, shelf_life

FORMATS = {
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "pdf": "application/pdf",
}
#: How far back the trend and the newest-scan-per-endpoint look.
HISTORY_DAYS = 3 * 365
TREND_MONTHS = 6
MAX_ACTIONS = 3

#: app.py installs these: the organization's display name, and the fix queue (/fix-next items).
ORG_NAME: Optional[Callable[[str], str]] = None
FIX_NEXT: Optional[Callable[[], List[Dict[str, Any]]]] = None

ACCENT = "B9F26B"
INK = "111614"
INK2 = "3D4642"
INK3 = "5E6863"
RULE = "D5DAD7"
BAR = "2F3A35"


# ── Reading the endpoints ───────────────────────────────────────────────────────────────────────


def _ts(value: Any) -> Optional[datetime]:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00").replace(" ", "T"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _day(value: Any) -> str:
    when = _ts(value)
    return when.strftime("%Y-%m-%d") if when else ""


def endpoint_state(fact: Dict[str, Any]) -> str:
    """``safe`` (the newest scan saw an ML-KEM key exchange), ``at_risk`` or ``unknown`` (not reached)."""
    status = str(fact.get("scan_status") or "ok").strip().lower()
    if status not in ("ok", "success", "completed", ""):
        return "unknown"
    family, _ = crypto_switch.observed(fact, "kex")
    return "safe" if family == "mlkem" else "at_risk"


def _host(asset_key: Any) -> str:
    text = str(asset_key or "").strip()
    return text[:-4] if text.endswith(":443") else text


def lifetime_years(value: Any) -> Optional[int]:
    """Whole years from an asset's confidentiality lifetime, only when it states a number ("25 years", "10y+")."""
    text = str(value or "").strip()
    if not re.search(r"\d", text):
        return None
    years = crypto_switch._lifetime_years(text)
    if years is None:
        return None
    return max(0, min(decrypt_window.SHELF_YEARS_MAX, int(math.ceil(years - 1e-9))))


# ── The content ─────────────────────────────────────────────────────────────────────────────────


def _risk(facts: List[Dict[str, Any]], fixes: List[Dict[str, Any]], data: Any, jurisdiction: Any,
          now: datetime) -> Optional[Dict[str, Any]]:
    if not facts:
        return None
    states = {str(f.get("asset_key") or ""): endpoint_state(f) for f in facts}
    at = [k for k, s in states.items() if s == "at_risk"]
    safe = [k for k, s in states.items() if s == "safe"]
    order = [str(x.get("asset_key") or "") for x in fixes]
    if at:
        ranked = sorted(at, key=lambda k: (order.index(k) if k in order else len(order), k))
        key, state = ranked[0], "at_risk"
    elif len(safe) == len(states):
        key, state = sorted(safe)[0], "safe"
    else:
        key, state = sorted(states)[0], "unknown"
    fact = next(f for f in facts if str(f.get("asset_key") or "") == key)
    item = next((x for x in fixes if str(x.get("asset_key") or "") == key), None)
    fixable = len([f for f in (item or {}).get("top_findings") or [] if (f or {}).get("remediation")])
    if state == "at_risk":
        # The classical key exchange is itself one setting to change (risk_sentence.settings_to_fix).
        fixable = max(1, fixable)
    observed = bool(str(fact.get("key_exchange") or "").strip()) or state != "at_risk"
    others = max(0, (len(at) if at else len(states)) - 1)
    out = risk_sentence.build(_host(key), state, fixable, data, jurisdiction, observed=observed, others=others, now=now)
    out["asset_key"] = key
    return out


def _deadline(risk: Optional[Dict[str, Any]], assets: List[Dict[str, Any]], data: Any, jurisdiction: Any,
              counts: Dict[str, int], now: datetime) -> Dict[str, Any]:
    est = decrypt_window.CRQC_ESTIMATE
    low, likely = int(est["low"]), int(est["likely"])
    year = now.year
    shelf = (risk or {}).get("data")
    if shelf is None and risk is None:
        # No scan yet: the kind of data is still known (chosen or assumed), so the deadline still is.
        shelf = risk_sentence._data(data, jurisdiction, "")
    longest: Optional[Tuple[int, Dict[str, Any]]] = None
    for a in assets:
        y = lifetime_years(a.get("confidentiality_lifetime"))
        if y is not None and (longest is None or y > longest[0]):
            longest = (y, a)
    years, basis = None, None
    if shelf is not None:
        years = int(shelf["years"])
        where = "" if shelf["jurisdiction"] == "INT" else f" under {shelf['jurisdiction_short']} law"
        basis = {"kind": "shelf_life", "assumed": bool(shelf["assumed"]), "subject": f"{shelf['label']}{where}",
                 "text": f"{'Assumed' if shelf['assumed'] else 'Chosen'} kind of data: {shelf['label']}{where}, "
                         f"{years} years (Shelf-Life v{shelf['edition']})"}
    if longest and (years is None or longest[0] > years):
        years = longest[0]
        a = longest[1]
        basis = {"kind": "inventory", "assumed": False, "asset_key": a.get("asset_key"),
                 "text": f"Longest confidentiality lifetime in your inventory: {a.get('asset_key')}, "
                         f"\"{a.get('confidentiality_lifetime')}\" ({years} years)",
                 "updated_at": _day(a.get("updated_at"))}
    out: Dict[str, Any] = {"is_estimate": True, "crqc_low": low, "crqc_likely": likely, "years": years, "basis": basis,
                           "source_label": decrypt_window.EXPOSURE_SOURCE_LABEL, "source_url": decrypt_window.EXPOSURE_SOURCE_URL}
    if years is None:
        out.update({"status": "not_measured", "value": "Not measured yet", "range": None,
                    "label": "How long your data must stay private is not known, so there is no deadline to show."})
        return out
    by_low, by_likely = low - years, likely - years
    out.update({"safe_by_low": by_low, "safe_by_likely": by_likely, "secret_until": year + years})
    scanned = counts["safe"] + counts["at_risk"]
    if scanned and counts["at_risk"] == 0 and counts["unknown"] == 0:
        out.update({"status": "met", "value": "Met", "range": None,
                    "label": "Every scanned endpoint already uses a quantum-safe key exchange, so data sent "
                             "over them from now on can't be read later with a quantum computer."})
        return out
    if by_likely <= year:
        out.update({"status": "overdue", "value": "Now", "range": f"a quantum computer could read it from {low} to {likely}",
                    "label": f"Data sent today must stay private until {year + years}, long after a quantum computer "
                             f"could read it. Every day on a classical key exchange adds to what can be read later."})
    elif by_low <= year:
        out.update({"status": "due", "value": "Now", "range": f"now to {by_likely}",
                    "label": f"By the earlier expert estimate ({low}) data sent today is already too late to protect; "
                             f"by the later one ({likely}), the last safe year is {by_likely}. "
                             f"Data sent today must stay private until {year + years}."})
    else:
        span = f"{by_low} to {by_likely}"
        out.update({"status": "ahead", "value": str(by_low), "range": span,
                    "label": f"Data sent after about {by_low} over a classical key exchange would still need to be "
                             f"private when a quantum computer could read it ({low} to {likely}, estimated)."})
    return out


def _share_series(history: List[Dict[str, Any]], now: datetime) -> List[Dict[str, Any]]:
    """Quantum-safe share of scanned endpoints at each month end, from each endpoint's newest scan by then."""
    rows = []
    for r in history:
        when = _ts(r.get("scanned_at"))
        key = str(r.get("asset_key") or "")
        if when and key:
            rows.append((when, key, endpoint_state(r)))
    if not rows:
        return []
    rows.sort(key=lambda x: x[0])
    first = rows[0][0]
    months: List[datetime] = []
    cursor = datetime(first.year, first.month, 1, tzinfo=timezone.utc)
    end = datetime(now.year, now.month, 1, tzinfo=timezone.utc)
    while cursor <= end:
        months.append(cursor)
        cursor = datetime(cursor.year + (cursor.month == 12), cursor.month % 12 + 1, 1, tzinfo=timezone.utc)
    months = months[-TREND_MONTHS:]
    points = []
    for start in months:
        nxt = datetime(start.year + (start.month == 12), start.month % 12 + 1, 1, tzinfo=timezone.utc)
        cut = min(nxt, now + timedelta(seconds=1))
        latest: Dict[str, str] = {}
        for when, key, state in rows:
            if when < cut:
                latest[key] = state
        known = [s for s in latest.values() if s != "unknown"]
        if not known:
            continue
        safe = sum(1 for s in known if s == "safe")
        points.append({"label": start.strftime("%b %Y"), "value": round(100.0 * safe / len(known)),
                       "safe": safe, "of": len(known), "as_of": (cut - timedelta(seconds=1)).strftime("%Y-%m-%d")})
    return points


def _trend(history: List[Dict[str, Any]], drills: List[Dict[str, Any]], now: datetime) -> Dict[str, Any]:
    share = _share_series(history, now)
    if len(share) >= 2:
        first, last = share[0], share[-1]
        words = "; ".join(f"{p['label']}: {p['value']}% ({p['safe']} of {p['of']})" for p in share)
        return {"kind": "pq_share", "is_estimate": False, "unit": "%",
                "title": "Quantum-safe share of scanned endpoints",
                "label": "Measured: each endpoint's newest scan at the end of each month",
                "points": share, "text": f"Quantum-safe share of scanned endpoints, by month: {words}.",
                "source": f"Morrow scans, {first['label']} to {last['as_of']}, measured"}
    timed = [d for d in drills if d.get("time_to_safe_days") is not None and d.get("days")]
    timed = sorted(timed, key=lambda d: str(d.get("created_at") or ""))[-TREND_MONTHS:]
    if len(timed) >= 2:
        points = [{"label": _day(d.get("created_at"))[5:] or "?", "value": int(d["time_to_safe_days"]),
                   "low": d["days"].get("low"), "high": d["days"].get("high"), "broken": d.get("broken") or "",
                   "as_of": _day(d.get("created_at"))} for d in timed]
        words = "; ".join(f"{p['as_of']}: about {p['value']} days (estimate {_n(p['low'])} to {_n(p['high'])})" for p in points)
        return {"kind": "fire_drill", "is_estimate": True, "unit": " d",
                "title": "Fire drill: days to make every affected system safe",
                "label": "Estimate from each drill (dry run); range in brackets",
                "points": points, "text": f"Fire drill time-to-safe, estimated: {words}.",
                "source": f"Morrow fire drills, {points[0]['as_of']} to {points[-1]['as_of']}, estimates"}
    return {"kind": None, "is_estimate": False, "points": [], "title": "Trend",
            "label": "",
            "text": "Trend not measured yet: it needs scans in two different months, or two fire drills.",
            "source": ""}


def _n(value: Any) -> str:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return "?"
    return str(int(round(number))) if number >= 1 or number == 0 else f"{number:.1f}"


def _actions(facts: List[Dict[str, Any]], fixes: List[Dict[str, Any]], deadline: Dict[str, Any],
             drills: List[Dict[str, Any]]) -> List[str]:
    if not facts:
        return ["Scan the hosts you run. Morrow then shows which ones are at risk and the exact change for each."]
    states = {str(f.get("asset_key") or ""): endpoint_state(f) for f in facts}
    order = [str(x.get("asset_key") or "") for x in fixes]
    at = sorted([k for k, s in states.items() if s == "at_risk"],
                key=lambda k: (order.index(k) if k in order else len(order), k))
    out: List[str] = []
    if at:
        more = f" and {len(at) - 1} other endpoint{'s' if len(at) != 2 else ''}" if len(at) > 1 else ""
        out.append(f"Turn on a quantum-safe key exchange (hybrid ML-KEM) on {_host(at[0])}{more}. "
                   "Make it safe in Morrow gives the exact change for each server.")
    seen = set()
    for item in fixes:
        if len(out) >= MAX_ACTIONS:
            break
        for f in item.get("top_findings") or []:
            text = str((f or {}).get("remediation") or "").strip().rstrip(".")
            if not text or text.lower() in seen or re.search(r"ml-?kem|post-quantum|hybrid", text, re.I):
                continue
            seen.add(text.lower())
            out.append(f"{text} ({_host(item.get('asset_key') or item.get('host'))}).")
            break
    unknown = [k for k, s in states.items() if s == "unknown"]
    if unknown and len(out) < MAX_ACTIONS:
        out.append(f"Re-scan {len(unknown)} endpoint{'s' if len(unknown) != 1 else ''} Morrow could not read, "
                   "so the picture is complete.")
    basis = deadline.get("basis") or {}
    if basis.get("assumed") and deadline.get("status") != "met" and len(out) < MAX_ACTIONS:
        out.append("Confirm which kind of data these systems carry: the deadline assumes "
                   f"{risk_sentence._lower_first(basis['subject'])}.")
    if not out and not drills:
        out.append("Run a fire drill to see how fast you could switch if an algorithm broke.")
    return out[:MAX_ACTIONS]


def build(org_name: str, facts: Sequence[Dict[str, Any]], assets: Sequence[Dict[str, Any]],
          fixes: Sequence[Dict[str, Any]], drills: Sequence[Dict[str, Any]], history: Sequence[Dict[str, Any]],
          data: Any = None, jurisdiction: Any = None, now: Optional[datetime] = None) -> Dict[str, Any]:
    """Everything on the slide, with its sources. Pure: no I/O; the clock is read only when ``now`` is None."""
    now = now or datetime.now(timezone.utc)
    facts, assets, fixes = list(facts or []), list(assets or []), list(fixes or [])
    drills, history = list(drills or []), list(history or [])
    counts = {"safe": 0, "at_risk": 0, "unknown": 0}
    for f in facts:
        counts[endpoint_state(f)] += 1
    total = len(facts)
    newest = max((_ts(f.get("scanned_at")) for f in facts if _ts(f.get("scanned_at"))), default=None)
    risk = _risk(facts, fixes, data, jurisdiction, now)
    deadline = _deadline(risk, assets, data, jurisdiction, counts, now)
    trend = _trend(history, drills, now)
    actions = _actions(facts, fixes, deadline, drills)
    scanned = counts["safe"] + counts["at_risk"]
    if not total:
        sentence = ("Not measured yet: no endpoint has been scanned, so Morrow can't say whether recorded "
                    "traffic could be read later.")
    else:
        sentence = risk["sentence"]
    stat = (f"Quantum-safe key exchange on {counts['safe']} of {scanned} scanned endpoint{'s' if scanned != 1 else ''}"
            + (f"; {counts['unknown']} could not be read" if counts["unknown"] else "")) if scanned else (
        "No endpoint could be read yet" if total else "No endpoint scanned yet")

    sources: List[str] = []
    today = now.strftime("%Y-%m-%d")
    if total:
        sources.append(f"Scans: {total} endpoint{'s' if total != 1 else ''}, newest scan {newest.strftime('%Y-%m-%d') if newest else 'undated'} (Morrow, measured)")
    else:
        sources.append("Scans: none yet")
    sources.append(f"Quantum year: estimate {deadline['crqc_low']} to {deadline['crqc_likely']}, "
                   f"{decrypt_window.EXPOSURE_SOURCE_LABEL} (published March 2026)")
    basis = deadline.get("basis")
    if basis and basis["kind"] == "shelf_life":
        payload = shelf_life.public_payload()
        sources.append(f"{basis['text']}, dated {payload.get('date') or 'undated'}")
    elif basis:
        sources.append(basis["text"] + (f", updated {basis['updated_at']}" if basis.get("updated_at") else ""))
    else:
        sources.append("Data lifetime: not measured yet")
    if trend["source"]:
        sources.append(f"Trend: {trend['source']}")
    if fixes and total:
        sources.append(f"Next actions: Morrow fix queue, newest scan {newest.strftime('%Y-%m-%d') if newest else 'undated'}")
    org = str(org_name or "").strip()
    sources.append(f"Generated {today} by Morrow" + (f" for {org}" if org else ""))

    return {
        "api_version": "v1",
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "date": today,
        "organization": org,
        "title": "Quantum risk",
        "headline": {"label": "Must be quantum-safe by", "value": deadline["value"], "range": deadline.get("range"),
                     "is_estimate": deadline["status"] not in ("met", "not_measured"), "status": deadline["status"],
                     "detail": deadline["label"]},
        "risk": {"sentence": sentence, "state": (risk or {}).get("state"), "measured": bool(total),
                 "assumption": (risk or {}).get("assumption")},
        "endpoints": {"total": total, **counts, "statement": stat},
        "deadline": deadline,
        "trend": trend,
        "actions": actions,
        "sources": sources,
    }


# ── Gathering (current tenant) ──────────────────────────────────────────────────────────────────


def gather(org_id: str, data: Any = None, jurisdiction: Any = None, now: Optional[datetime] = None) -> Dict[str, Any]:
    """Read the organization's data and build the slide. Reads only."""
    import db

    from services import fire_drill

    now = now or datetime.now(timezone.utc)
    facts = db.latest_scan_facts_for_org(limit=5000)
    assets = db.list_assets(limit=5000)
    since = (now - timedelta(days=HISTORY_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        history = db.list_scan_results_since(since, limit=50000)
    except Exception:
        history = []
    try:
        drills = fire_drill.list_drills(org_id, limit=TREND_MONTHS * 2)
    except Exception:
        drills = []
    try:
        fixes = list((FIX_NEXT or (lambda: []))() or [])
    except Exception:
        fixes = []
    try:
        name = (ORG_NAME or (lambda _o: ""))(org_id) or ""
    except Exception:
        name = ""
    return build(name, facts, assets, fixes, drills, history, data=data, jurisdiction=jurisdiction, now=now)


def filename(content: Dict[str, Any], fmt: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", str(content.get("organization") or "").lower()).strip("-")[:40]
    return f"board-slide{'-' + slug if slug else ''}-{content.get('date') or 'undated'}.{fmt}"


# ── Layout (shared by both formats) ─────────────────────────────────────────────────────────────

#: The slide in inches, 13.333 x 7.5 (16:9). Boxes are (x, y, w, h).
W, H = 12192000 / 914400, 7.5
MARGIN = 0.6
LEFT_W = 5.0
RIGHT_X = MARGIN + LEFT_W + 0.55
RIGHT_W = W - RIGHT_X - MARGIN
FOOT_Y = 6.55


def _eyebrow(content: Dict[str, Any]) -> str:
    parts = ["QUANTUM RISK"] + ([content["organization"]] if content.get("organization") else []) + [content["date"]]
    return "  ·  ".join(parts)


def _chart_bars(trend: Dict[str, Any]) -> List[Dict[str, Any]]:
    points = trend.get("points") or []
    if not points:
        return []
    top = 100.0 if trend["kind"] == "pq_share" else max(1.0, max(float(p.get("high") or p["value"]) for p in points))
    return [{"label": p["label"], "value": p["value"], "ratio": max(0.0, min(1.0, float(p["value"]) / top)),
             "text": f"{p['value']}%" if trend["kind"] == "pq_share" else f"{p['value']} d",
             "last": i == len(points) - 1} for i, p in enumerate(points)]


# ── PPTX ────────────────────────────────────────────────────────────────────────────────────────

EMU = 914400
_NS = ('xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
       'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
       'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"')
_XML = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
_BAD_XML = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f￾￿]")


def _x(text: Any) -> str:
    return _xml_escape(_BAD_XML.sub("", str(text if text is not None else "")), {'"': "&quot;"})


def _e(inches: float) -> int:
    return int(round(inches * EMU))


class _Slide:
    def __init__(self) -> None:
        self.shapes: List[str] = []
        self.next_id = 2

    def _id(self) -> int:
        self.next_id += 1
        return self.next_id

    def text(self, name: str, box: Tuple[float, float, float, float], paragraphs: List[List[Dict[str, Any]]],
             anchor: str = "t", autofit: bool = True) -> str:
        x, y, w, h = box
        paras = []
        for runs in paragraphs:
            align = runs[0].get("align", "l") if runs else "l"
            space = runs[0].get("space_after", 0) if runs else 0
            ppr = f'<a:pPr algn="{align}"><a:spcAft><a:spcPts val="{int(space * 100)}"/></a:spcAft></a:pPr>'
            body = "".join(
                f'<a:r><a:rPr lang="en-GB" sz="{int(r.get("size", 14) * 100)}" b="{1 if r.get("bold") else 0}" dirty="0">'
                f'<a:solidFill><a:srgbClr val="{r.get("color", INK)}"/></a:solidFill>'
                f'<a:latin typeface="Arial"/><a:cs typeface="Arial"/></a:rPr><a:t>{_x(r["text"])}</a:t></a:r>'
                for r in runs)
            paras.append(f"<a:p>{ppr}{body}</a:p>")
        fit = "<a:normAutofit/>" if autofit else "<a:noAutofit/>"
        xml = (f'<p:sp><p:nvSpPr><p:cNvPr id="{self._id()}" name="{_x(name)}"/><p:cNvSpPr txBox="1"/><p:nvPr/></p:nvSpPr>'
               f'<p:spPr><a:xfrm><a:off x="{_e(x)}" y="{_e(y)}"/><a:ext cx="{_e(w)}" cy="{_e(h)}"/></a:xfrm>'
               '<a:prstGeom prst="rect"><a:avLst/></a:prstGeom><a:noFill/></p:spPr>'
               f'<p:txBody><a:bodyPr wrap="square" lIns="0" tIns="0" rIns="0" bIns="0" anchor="{anchor}">{fit}</a:bodyPr>'
               f'<a:lstStyle/>{"".join(paras)}</p:txBody></p:sp>')
        self.shapes.append(xml)
        return xml

    def rect(self, name: str, box: Tuple[float, float, float, float], fill: str, line: str = "", into: Optional[List[str]] = None) -> None:
        x, y, w, h = box
        ln = (f'<a:ln w="9525"><a:solidFill><a:srgbClr val="{line}"/></a:solidFill></a:ln>' if line else "<a:ln><a:noFill/></a:ln>")
        xml = (f'<p:sp><p:nvSpPr><p:cNvPr id="{self._id()}" name="{_x(name)}"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>'
               f'<p:spPr><a:xfrm><a:off x="{_e(x)}" y="{_e(y)}"/><a:ext cx="{max(1, _e(w))}" cy="{max(1, _e(h))}"/></a:xfrm>'
               f'<a:prstGeom prst="rect"><a:avLst/></a:prstGeom><a:solidFill><a:srgbClr val="{fill}"/></a:solidFill>{ln}</p:spPr></p:sp>')
        (self.shapes if into is None else into).append(xml)

    def group(self, name: str, descr: str, box: Tuple[float, float, float, float], children: List[str]) -> None:
        x, y, w, h = box
        off, ext = f'x="{_e(x)}" y="{_e(y)}"', f'cx="{_e(w)}" cy="{_e(h)}"'
        self.shapes.append(
            f'<p:grpSp><p:nvGrpSpPr><p:cNvPr id="{self._id()}" name="{_x(name)}" descr="{_x(descr)}"/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>'
            f'<p:grpSpPr><a:xfrm><a:off {off}/><a:ext {ext}/><a:chOff {off}/><a:chExt {ext}/></a:xfrm></p:grpSpPr>'
            f'{"".join(children)}</p:grpSp>')

    def xml(self) -> str:
        return (f'{_XML}<p:sld {_NS}><p:cSld><p:bg><p:bgPr><a:solidFill><a:srgbClr val="FFFFFF"/></a:solidFill>'
                '<a:effectLst/></p:bgPr></p:bg><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/>'
                '</p:nvGrpSpPr><p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/>'
                f'<a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>{"".join(self.shapes)}</p:spTree></p:cSld>'
                '<p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sld>')


def _headline_size(value: str) -> int:
    return 110 if len(value) <= 4 else 54 if len(value) <= 10 else 40


def _slide_xml(c: Dict[str, Any]) -> str:
    s = _Slide()
    hl, trend = c["headline"], c["trend"]
    s.rect("Accent", (MARGIN, 0.55, 0.5, 0.07), ACCENT)
    s.text("Eyebrow", (MARGIN + 0.65, 0.42, W - 2 * MARGIN - 0.65, 0.32),
           [[{"text": _eyebrow(c), "size": 11, "bold": True, "color": INK3}]], autofit=False)
    # Left: the one number.
    s.text("Deadline label", (MARGIN, 1.05, LEFT_W, 0.45), [[{"text": hl["label"], "size": 18, "bold": True, "color": INK2}]])
    s.text("Deadline", (MARGIN, 1.45, LEFT_W, 2.0), [[{"text": hl["value"], "size": _headline_size(hl["value"]), "bold": True}]],
           anchor="ctr")
    lines = []
    if hl.get("range"):
        lines.append([{"text": f"Estimate: {hl['range']}", "size": 16, "bold": True, "color": INK, "space_after": 6}])
    lines.append([{"text": hl["detail"], "size": 13, "color": INK2, "space_after": 8}])
    lines.append([{"text": c["endpoints"]["statement"] + ".", "size": 13, "color": INK2}])
    s.text("Deadline detail", (MARGIN, 3.5, LEFT_W, 2.8), lines)
    # Right: the sentence, the trend, the actions.
    s.text("Risk sentence", (RIGHT_X, 1.05, RIGHT_W, 1.75), [[{"text": c["risk"]["sentence"], "size": 18, "bold": True}]])
    s.rect("Rule", (RIGHT_X, 2.95, RIGHT_W, 0.012), RULE)
    s.text("Trend title", (RIGHT_X, 3.08, RIGHT_W, 0.5),
           [[{"text": trend["title"], "size": 12, "bold": True, "color": INK}],
            [{"text": trend["label"], "size": 10, "color": INK3}]])
    bars = _chart_bars(trend)
    cy, ch = 3.65, 1.1
    if bars:
        children: List[str] = []
        slot = min(1.0, RIGHT_W / len(bars))
        bw = slot * 0.55
        for i, b in enumerate(bars):
            bx = RIGHT_X + i * slot
            bh = max(0.02, (ch - 0.25) * b["ratio"])
            s.rect(f"Bar {b['label']}", (bx, cy + (ch - 0.25) - bh, bw, bh), ACCENT if b["last"] else BAR,
                   line=INK if b["last"] else "", into=children)
            children.append(s.text(f"Value {b['label']}", (bx - 0.1, cy + (ch - 0.25) - bh - 0.24, bw + 0.2, 0.22),
                                   [[{"text": b["text"], "size": 9, "bold": True, "align": "ctr", "color": INK}]], autofit=False))
            children.append(s.text(f"Month {b['label']}", (bx - 0.2, cy + ch - 0.2, bw + 0.4, 0.2),
                                   [[{"text": b["label"], "size": 8, "align": "ctr", "color": INK3}]], autofit=False))
        s.rect("Chart baseline", (RIGHT_X, cy + ch - 0.25, slot * len(bars) - (slot - bw), 0.01), INK3, into=children)
        # Text boxes were appended to the slide too; keep them only inside the group.
        for child in children:
            if child in s.shapes:
                s.shapes.remove(child)
        s.group("Trend chart", trend["text"], (RIGHT_X - 0.2, cy - 0.3, RIGHT_W + 0.2, ch + 0.3), children)
    else:
        s.text("Trend", (RIGHT_X, cy, RIGHT_W, 0.5), [[{"text": trend["text"], "size": 12, "color": INK2}]])
    acts = [[{"text": "Next", "size": 12, "bold": True, "space_after": 3}]]
    acts += [[{"text": f"{i}.  ", "size": 13, "bold": True}, {"text": a, "size": 13, "color": INK, "space_after": 3}]
             for i, a in enumerate(c["actions"], 1)]
    s.text("Next actions", (RIGHT_X, 4.95, RIGHT_W, 1.5), acts)
    # Footer: every source with its date.
    s.rect("Footer rule", (MARGIN, FOOT_Y - 0.08, W - 2 * MARGIN, 0.01), RULE)
    s.text("Sources", (MARGIN, FOOT_Y, W - 2 * MARGIN, 0.75),
           [[{"text": "Sources: " + "  ·  ".join(c["sources"]) + ". Estimates are labelled; nothing is filled in where data is missing.",
              "size": 8, "color": INK3}]])
    return s.xml()


_THEME = (_XML + '<a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" name="Morrow">'
          '<a:themeElements><a:clrScheme name="Morrow">'
          '<a:dk1><a:srgbClr val="111614"/></a:dk1><a:lt1><a:srgbClr val="FFFFFF"/></a:lt1>'
          '<a:dk2><a:srgbClr val="2F3A35"/></a:dk2><a:lt2><a:srgbClr val="F2F4F3"/></a:lt2>'
          '<a:accent1><a:srgbClr val="B9F26B"/></a:accent1><a:accent2><a:srgbClr val="2F3A35"/></a:accent2>'
          '<a:accent3><a:srgbClr val="5E6863"/></a:accent3><a:accent4><a:srgbClr val="8A948F"/></a:accent4>'
          '<a:accent5><a:srgbClr val="D5DAD7"/></a:accent5><a:accent6><a:srgbClr val="3D4642"/></a:accent6>'
          '<a:hlink><a:srgbClr val="2F3A35"/></a:hlink><a:folHlink><a:srgbClr val="5E6863"/></a:folHlink></a:clrScheme>'
          '<a:fontScheme name="Morrow"><a:majorFont><a:latin typeface="Arial"/><a:ea typeface=""/><a:cs typeface=""/></a:majorFont>'
          '<a:minorFont><a:latin typeface="Arial"/><a:ea typeface=""/><a:cs typeface=""/></a:minorFont></a:fontScheme>'
          '<a:fmtScheme name="Morrow"><a:fillStyleLst>'
          '<a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill>'
          '<a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:fillStyleLst><a:lnStyleLst>'
          '<a:ln w="6350"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln>'
          '<a:ln w="12700"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln>'
          '<a:ln w="19050"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln></a:lnStyleLst>'
          '<a:effectStyleLst><a:effectStyle><a:effectLst/></a:effectStyle><a:effectStyle><a:effectLst/></a:effectStyle>'
          '<a:effectStyle><a:effectLst/></a:effectStyle></a:effectStyleLst><a:bgFillStyleLst>'
          '<a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill>'
          '<a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:bgFillStyleLst></a:fmtScheme></a:themeElements>'
          '<a:objectDefaults/><a:extraClrSchemeLst/></a:theme>')

_EMPTY_TREE = ('<p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr><a:xfrm>'
               '<a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr></p:spTree>')
_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_CT = "application/vnd.openxmlformats-officedocument"


def _rels(*items: Tuple[str, str, str]) -> str:
    body = "".join(f'<Relationship Id="{i}" Type="{t}" Target="{target}"/>' for i, t, target in items)
    return f'{_XML}<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">{body}</Relationships>'


def render_pptx(content: Dict[str, Any]) -> bytes:
    """One 16:9 slide. Text stays editable; the chart is shapes with its data in the group's alt text."""
    title = f"Board slide: quantum risk{' - ' + content['organization'] if content.get('organization') else ''} ({content['date']})"
    parts = {
        "[Content_Types].xml": (
            f'{_XML}<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            f'<Override PartName="/ppt/presentation.xml" ContentType="{_CT}.presentationml.presentation.main+xml"/>'
            f'<Override PartName="/ppt/slideMasters/slideMaster1.xml" ContentType="{_CT}.presentationml.slideMaster+xml"/>'
            f'<Override PartName="/ppt/slideLayouts/slideLayout1.xml" ContentType="{_CT}.presentationml.slideLayout+xml"/>'
            f'<Override PartName="/ppt/slides/slide1.xml" ContentType="{_CT}.presentationml.slide+xml"/>'
            f'<Override PartName="/ppt/theme/theme1.xml" ContentType="{_CT}.theme+xml"/>'
            f'<Override PartName="/ppt/presProps.xml" ContentType="{_CT}.presentationml.presProps+xml"/>'
            f'<Override PartName="/ppt/viewProps.xml" ContentType="{_CT}.presentationml.viewProps+xml"/>'
            f'<Override PartName="/ppt/tableStyles.xml" ContentType="{_CT}.presentationml.tableStyles+xml"/>'
            '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
            f'<Override PartName="/docProps/app.xml" ContentType="{_CT}.extended-properties+xml"/></Types>'),
        "_rels/.rels": _rels(
            ("rId1", f"{_REL}/officeDocument", "ppt/presentation.xml"),
            ("rId2", "http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties", "docProps/core.xml"),
            ("rId3", f"{_REL}/extended-properties", "docProps/app.xml")),
        "docProps/core.xml": (
            f'{_XML}<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            f'<dc:title>{_x(title)}</dc:title><dc:creator>Morrow</dc:creator>'
            f'<dcterms:created xsi:type="dcterms:W3CDTF">{content["generated_at"]}</dcterms:created></cp:coreProperties>'),
        "docProps/app.xml": (
            f'{_XML}<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
            '<Application>Morrow</Application><Slides>1</Slides></Properties>'),
        "ppt/presentation.xml": (
            f'{_XML}<p:presentation {_NS} saveSubsetFonts="1">'
            '<p:sldMasterIdLst><p:sldMasterId id="2147483648" r:id="rId1"/></p:sldMasterIdLst>'
            '<p:sldIdLst><p:sldId id="256" r:id="rId2"/></p:sldIdLst>'
            f'<p:sldSz cx="{_e(W)}" cy="{_e(H)}"/><p:notesSz cx="6858000" cy="9144000"/></p:presentation>'),
        "ppt/_rels/presentation.xml.rels": _rels(
            ("rId1", f"{_REL}/slideMaster", "slideMasters/slideMaster1.xml"),
            ("rId2", f"{_REL}/slide", "slides/slide1.xml"),
            ("rId3", f"{_REL}/theme", "theme/theme1.xml"),
            ("rId4", f"{_REL}/presProps", "presProps.xml"),
            ("rId5", f"{_REL}/viewProps", "viewProps.xml"),
            ("rId6", f"{_REL}/tableStyles", "tableStyles.xml")),
        "ppt/presProps.xml": f"{_XML}<p:presentationPr {_NS}/>",
        "ppt/viewProps.xml": f"{_XML}<p:viewPr {_NS}/>",
        "ppt/tableStyles.xml": (f'{_XML}<a:tblStyleLst xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
                                'def="{5C22544A-7EE6-4342-B048-85BDC9FD1C3A}"/>'),
        "ppt/theme/theme1.xml": _THEME,
        "ppt/slideMasters/slideMaster1.xml": (
            f'{_XML}<p:sldMaster {_NS}><p:cSld><p:bg><p:bgRef idx="1001"><a:schemeClr val="bg1"/></p:bgRef></p:bg>'
            f'{_EMPTY_TREE}</p:cSld><p:clrMap bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" accent1="accent1" accent2="accent2" '
            'accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/>'
            '<p:sldLayoutIdLst><p:sldLayoutId id="2147483649" r:id="rId1"/></p:sldLayoutIdLst>'
            '<p:txStyles><p:titleStyle/><p:bodyStyle/><p:otherStyle/></p:txStyles></p:sldMaster>'),
        "ppt/slideMasters/_rels/slideMaster1.xml.rels": _rels(
            ("rId1", f"{_REL}/slideLayout", "../slideLayouts/slideLayout1.xml"),
            ("rId2", f"{_REL}/theme", "../theme/theme1.xml")),
        "ppt/slideLayouts/slideLayout1.xml": (
            f'{_XML}<p:sldLayout {_NS} type="blank" preserve="1"><p:cSld name="Blank">{_EMPTY_TREE}</p:cSld>'
            '<p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sldLayout>'),
        "ppt/slideLayouts/_rels/slideLayout1.xml.rels": _rels(("rId1", f"{_REL}/slideMaster", "../slideMasters/slideMaster1.xml")),
        "ppt/slides/slide1.xml": _slide_xml(content),
        "ppt/slides/_rels/slide1.xml.rels": _rels(("rId1", f"{_REL}/slideLayout", "../slideLayouts/slideLayout1.xml")),
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, xml in parts.items():
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, xml.encode("utf-8"))
    return buf.getvalue()


# ── PDF ─────────────────────────────────────────────────────────────────────────────────────────


def _latin(text: Any) -> str:
    """The standard PDF fonts cover cp1252; anything else would print as a box."""
    return str(text if text is not None else "").encode("cp1252", "replace").decode("cp1252")


def render_pdf(content: Dict[str, Any]) -> bytes:
    """The same slide as one landscape 16:9 PDF page (960 x 540 pt), text as text, chart as vector shapes."""
    from reportlab.lib.colors import HexColor
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.pdfgen import canvas
    from reportlab.platypus import Paragraph

    pt = 72.0
    page_w, page_h = W * pt, H * pt
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=(page_w, page_h), pageCompression=1)
    org = content.get("organization") or ""
    c.setTitle(_latin(f"Board slide: quantum risk{' - ' + org if org else ''} ({content['date']})"))
    c.setAuthor("Morrow")
    c.setSubject(_latin(content["trend"]["text"]))
    c.setCreator("Morrow")

    def col(hex_value: str):
        return HexColor("#" + hex_value)

    def para(text: str, box: Tuple[float, float, float, float], size: float, bold: bool = False, color: str = INK,
             leading: float = 1.2, align: int = 0) -> float:
        x, y, w, h = box
        style = ParagraphStyle("s", fontName="Helvetica-Bold" if bold else "Helvetica", fontSize=size,
                               leading=size * leading, textColor=col(color), alignment=align)
        p = Paragraph(_xml_escape(_latin(text)), style)
        _, ph = p.wrap(w * pt, h * pt)
        p.drawOn(c, x * pt, page_h - y * pt - ph)
        return ph / pt

    def rect(box: Tuple[float, float, float, float], fill: str, line: str = "") -> None:
        x, y, w, h = box
        c.setFillColor(col(fill))
        if line:
            c.setStrokeColor(col(line))
            c.setLineWidth(0.75)
        c.rect(x * pt, page_h - (y + h) * pt, w * pt, h * pt, fill=1, stroke=1 if line else 0)

    hl, trend = content["headline"], content["trend"]
    rect((MARGIN, 0.55, 0.5, 0.07), ACCENT)
    para(_eyebrow(content).replace("·", "-"), (MARGIN + 0.65, 0.47, W - 2 * MARGIN - 0.65, 0.3), 11, True, INK3)
    para(hl["label"], (MARGIN, 1.05, LEFT_W, 0.45), 18, True, INK2)
    size = _headline_size(hl["value"])
    para(hl["value"], (MARGIN, 1.5 + max(0.0, (1.9 - size * 1.05 / pt) / 2), LEFT_W, 1.9), size, True, INK, leading=1.0)
    y = 3.5
    if hl.get("range"):
        y += para(f"Estimate: {hl['range']}", (MARGIN, y, LEFT_W, 0.4), 16, True) + 0.08
    y += para(hl["detail"], (MARGIN, y, LEFT_W, 1.6), 13, False, INK2) + 0.1
    para(content["endpoints"]["statement"] + ".", (MARGIN, y, LEFT_W, 0.6), 13, False, INK2)

    para(content["risk"]["sentence"], (RIGHT_X, 1.05, RIGHT_W, 1.8), 18, True)
    rect((RIGHT_X, 2.95, RIGHT_W, 0.012), RULE)
    para(trend["title"], (RIGHT_X, 3.08, RIGHT_W, 0.25), 12, True)
    para(trend["label"], (RIGHT_X, 3.3, RIGHT_W, 0.25), 10, False, INK3)
    bars = _chart_bars(trend)
    cy, ch = 3.65, 1.1
    if bars:
        slot = min(1.0, RIGHT_W / len(bars))
        bw = slot * 0.55
        for i, b in enumerate(bars):
            bx = RIGHT_X + i * slot
            bh = max(0.02, (ch - 0.25) * b["ratio"])
            rect((bx, cy + (ch - 0.25) - bh, bw, bh), ACCENT if b["last"] else BAR, INK if b["last"] else "")
            para(b["text"], (bx - 0.1, cy + (ch - 0.25) - bh - 0.2, bw + 0.2, 0.2), 9, True, INK, align=1)
            para(b["label"], (bx - 0.2, cy + ch - 0.2, bw + 0.4, 0.2), 8, False, INK3, align=1)
        rect((RIGHT_X, cy + ch - 0.25, slot * len(bars) - (slot - bw), 0.01), INK3)
    else:
        para(trend["text"], (RIGHT_X, cy, RIGHT_W, 0.5), 12, False, INK2)
    y = 4.95
    y += para("Next", (RIGHT_X, y, RIGHT_W, 0.25), 12, True) + 0.04
    for i, a in enumerate(content["actions"], 1):
        y += para(f"{i}.  {a}", (RIGHT_X, y, RIGHT_W, 0.6), 13) + 0.04
    rect((MARGIN, FOOT_Y - 0.08, W - 2 * MARGIN, 0.01), RULE)
    used = para("Sources: " + "  -  ".join(content["sources"]) + ". Estimates are labelled; nothing is filled in where data is missing.",
                (MARGIN, FOOT_Y, W - 2 * MARGIN, 0.75), 8, False, INK3)
    if bars:
        # The chart's text alternative, in words, under the sources, for screen readers and print.
        para(trend["text"], (MARGIN, FOOT_Y + used + 0.04, W - 2 * MARGIN, 0.4), 7, False, INK3)
    c.showPage()
    c.save()
    return buf.getvalue()


def render(content: Dict[str, Any], fmt: str) -> bytes:
    if fmt == "pptx":
        return render_pptx(content)
    if fmt == "pdf":
        return render_pdf(content)
    raise ValueError(f"unknown format {fmt!r}")
