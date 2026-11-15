"""Quantum fire drill: "algorithm X was broken this morning. How long until we are safe?"

A drill runs the crypto kill switch's own planner (services/crypto_switch.build_plan: pre-flight
against the organization's policy, every affected asset from the newest scans, owner, priority and
the change for each stack) against the organization's real inventory, in dry run. It reports one
number, time-to-safe: how long until everything that depends on the broken algorithm would be on
the fallback.

What a drill never does: declare a kill-switch incident, open a pull request, request a rescan,
push a configuration, send a notification or webhook, or revoke anything. build_plan is pure; the
only rows a drill writes are its own record (fire_drills) and one entry in the organization's audit
log. test_fire_drill.py proves it.

How the number is worked out (estimate(), pure):

* Every affected asset takes one of three paths. Automated: the asset has a linked repository and
  the organization has a code host connected, so the kill switch would open a pull request. Manual:
  someone applies the configuration by hand. Vendor: TLS ends at a CDN or cloud load balancer
  (named in the asset's own record), so the change is a vendor setting -- or, when the vendor does
  not offer the fallback, a wait for the vendor.
* Assets are grouped by owner. Owners work in parallel; each owner's lane is their response time
  (paid once) plus the hands-on time of every change they apply by hand.
* Response time is measured where Morrow has history: the time from a proposed fix to its merge in
  this organization's remediations and kill-switch requests, per owner (two merges or more) or
  across the organization (three or more). Without history it is an assumption, stated, and wide.
* Hands-on time per manual change comes from the remediation playbook for that stack.
* Time-to-safe is the slowest lane. The range is the slowest low and the slowest high. Anything
  Morrow does not know (no owner, no history, never-scanned assets, unconfirmed key sizes, a
  vendor's roadmap) is listed and widens the range instead of moving the middle.
"""

from __future__ import annotations

import json
import math
import re
import secrets
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from db_feature_store import feature_conn
from services import crypto_switch

# ── What can be drilled ─────────────────────────────────────────────────────────────────────────

#: Offered in the console. Any name crypto_switch.resolve() knows is accepted by the API.
DRILL_ALGORITHMS: List[Dict[str, str]] = [
    {"name": "X25519", "label": "X25519 (classical key exchange)"},
    {"name": "ML-KEM", "label": "ML-KEM (post-quantum key exchange)"},
    {"name": "RSA-2048", "label": "RSA-2048 (certificates)"},
    {"name": "ECDSA-P256", "label": "ECDSA P-256 (certificates)"},
]
DEFAULT_ALGORITHM = "X25519"

CADENCES: Dict[str, int] = {"off": 0, "monthly": 1, "quarterly": 3}  # months between drills

# ── Assumptions (used only where the organization's own data is missing; every one is reported) ──

#: Days from "a fix is proposed" to "it is merged or applied", when no merge is on record.
ASSUMED_RESPONSE_DAYS = (1.0, 7.0, 30.0)
#: Days to find someone for an asset with no named owner.
UNOWNED_TRIAGE_DAYS = (1.0, 3.0, 10.0)
#: Hands-on time per manual change when no playbook covers the stack (hours).
ASSUMED_HANDS_ON_HOURS = (2.0, 4.0, 16.0)
#: Days until a CDN / cloud load balancer offers the fallback, when it does not document it today.
VENDOR_WAIT_DAYS = (7.0, 30.0, 180.0)
WORK_HOURS_PER_DAY = 8.0
MIN_OWNER_SAMPLES = 2
MIN_ORG_SAMPLES = 3
STALE_SCAN_DAYS = 90
MANUAL_RUN_COOLDOWN_SECONDS = 30
#: The range's upper end is not stretched past a year; the drill says when it is capped.
MAX_HIGH_DAYS = 365.0


class DrillError(Exception):
    def __init__(self, status_code: int, detail: Any):
        super().__init__(str(detail))
        self.status_code = status_code
        self.detail = detail


def _now_dt() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ts(value: Any) -> Optional[datetime]:
    return crypto_switch._ts(value)


def _norm(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value or "").lower())


def _quantile(values: List[float], q: float) -> float:
    data = sorted(values)
    if not data:
        return 0.0
    pos = (len(data) - 1) * q
    lo, hi = int(math.floor(pos)), int(math.ceil(pos))
    return data[lo] + (data[hi] - data[lo]) * (pos - lo)


def _assets(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def _r(value: float) -> float:
    return round(float(value), 1)


# ── Measured response times ─────────────────────────────────────────────────────────────────────

def merge_samples(remediations: Iterable[Dict[str, Any]], switch_items: Iterable[Dict[str, Any]],
                  owner_of: Callable[[str], str]) -> List[Dict[str, Any]]:
    """(owner, days) for every fix with both a start and a merge time. Pure."""
    out: List[Dict[str, Any]] = []
    for row in remediations or []:
        start, end = _ts(row.get("created_at")), _ts(row.get("merged_at"))
        if start and end and end >= start:
            out.append({"owner": owner_of(str(row.get("asset_key") or "")), "days": (end - start).total_seconds() / 86400.0,
                        "source": "remediation"})
    for row in switch_items or []:
        start, end = _ts(row.get("opened_at")), _ts(row.get("merged_at"))
        if start and end and end >= start:
            owner = str(row.get("owner") or "") or owner_of(str(row.get("asset_key") or ""))
            out.append({"owner": owner, "days": (end - start).total_seconds() / 86400.0, "source": "kill_switch"})
    return out


def response_model(samples: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Per-owner and organization-wide response ranges from merge samples. Pure."""
    by_owner: Dict[str, List[float]] = {}
    for s in samples:
        if s["owner"]:
            by_owner.setdefault(s["owner"], []).append(float(s["days"]))
    every = [float(s["days"]) for s in samples]
    org = None
    if len(every) >= MIN_ORG_SAMPLES:
        org = {"samples": len(every), "low": _quantile(every, 0.25), "likely": _quantile(every, 0.5), "high": _quantile(every, 0.9)}
    owners = {o: {"samples": len(v), "low": min(v), "likely": _quantile(v, 0.5), "high": max(v)}
              for o, v in by_owner.items() if len(v) >= MIN_OWNER_SAMPLES}
    return {"org": org, "owners": owners, "samples": len(every)}


def response_for(owner: str, model: Dict[str, Any]) -> Tuple[Tuple[float, float, float], str, bool]:
    """((low, likely, high) days, basis, measured)."""
    hit = (model.get("owners") or {}).get(owner) if owner else None
    if hit:
        return (hit["low"], hit["likely"], hit["high"]), f"measured: {hit['samples']} merged fixes by this owner", True
    org = model.get("org")
    if org:
        return (org["low"], org["likely"], org["high"]), f"measured: {org['samples']} merged fixes across your organization", True
    return ASSUMED_RESPONSE_DAYS, "assumed: no merged fix on record to measure", False


# ── Paths ───────────────────────────────────────────────────────────────────────────────────────

def _recipes() -> Dict[str, Any]:
    try:
        from services import make_safe

        return make_safe.recipes().get("recipes") or {}
    except Exception:
        return {}


def vendor_for(asset: Dict[str, Any], recipes: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, str]]:
    """The CDN or cloud load balancer the asset's own record says terminates its TLS, if any. Pure:
    reads only the inventory record (metadata and tags), never the network."""
    recipes = _recipes() if recipes is None else recipes
    edges = {k: v for k, v in recipes.items() if v.get("kind") in ("cdn", "cloud_lb")}
    if not edges:
        return None
    meta = asset.get("metadata") if isinstance(asset.get("metadata"), dict) else {}
    hints = [meta.get(k) for k in ("tls_terminator", "cdn", "vendor", "edge", "stack", "server_type", "load_balancer")]
    hints += list(asset.get("tags") or [])
    for hint in hints:
        text = _norm(hint)
        if not text:
            continue
        for key, info in edges.items():
            if text == _norm(key) or text == _norm(info.get("name")) or (len(_norm(key)) >= 6 and _norm(key) in text):
                return {"id": key, "name": str(info.get("name") or key), "support": str(info.get("support") or "unknown")}
    return None


def hands_on_hours(server_type: str) -> Tuple[Tuple[float, float, float], str, bool]:
    """Hands-on hours for one manual change, from the remediation playbook for the stack."""
    try:
        from services import remediation_playbooks

        pb = remediation_playbooks.recommend_playbook(str(server_type or ""))
    except Exception:
        pb = None
    if pb:
        nums = [float(n) for n in re.findall(r"\d+(?:\.\d+)?", str(pb.get("estimated_time") or ""))]
        if nums:
            lo, hi = min(nums), max(nums)
            return (lo, (lo + hi) / 2.0, hi), f"the {pb['name']} playbook ({pb['estimated_time']})", True
    return ASSUMED_HANDS_ON_HOURS, "assumed: no playbook for this stack", False


# ── The estimate (pure) ─────────────────────────────────────────────────────────────────────────

def estimate(plan: Dict[str, Any], assets: Iterable[Dict[str, Any]], *, has_code_host: bool,
             response: Dict[str, Any], unscanned: int = 0, stale: int = 0,
             recipes: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Time-to-safe from a kill-switch plan. Returns days (low/likely/high), lanes, assumptions, gaps."""
    assets_by_key = {str(a.get("asset_key") or ""): a for a in assets or []}
    fallback = plan.get("fallback") or {}
    items = plan.get("items") or []
    recipes = _recipes() if recipes is None else recipes
    lanes: Dict[str, Dict[str, Any]] = {}
    assumptions: List[str] = []
    gaps: List[str] = []
    counts = {"automated": 0, "manual": 0, "vendor_setting": 0, "vendor_wait": 0}
    unconfirmed = 0

    def note(lst: List[str], text: str) -> None:
        if text not in lst:
            lst.append(text)

    for item in items:
        key = item["asset_key"]
        asset = assets_by_key.get(key) or {"asset_key": key}
        if not item.get("observed_confirmed", True):
            unconfirmed += 1
        vendor = vendor_for(asset, recipes)
        owner = str(item.get("owner") or "")
        if vendor:
            ready = (fallback.get("kind") == "kex" and fallback.get("post_quantum")
                     and vendor["support"] in ("default_on", "opt_in"))
            if not ready:
                lane_id = "vendor:" + vendor["id"]
                lane = lanes.setdefault(lane_id, {"id": lane_id, "kind": "vendor_wait", "label": vendor["name"], "assets": [],
                                                  "days": VENDOR_WAIT_DAYS, "measured": False,
                                                  "basis": f"assumed: Morrow cannot see when {vendor['name']} would offer "
                                                           f"{fallback.get('name')}"})
                lane["assets"].append(key)
                counts["vendor_wait"] += 1
                note(assumptions, f"A vendor that does not document {fallback.get('name')} today takes "
                                  f"{VENDOR_WAIT_DAYS[0]:g} to {VENDOR_WAIT_DAYS[2]:g} days to offer it "
                                  f"({VENDOR_WAIT_DAYS[1]:g} likely). No data behind this: it is the widest guess in the drill.")
                continue
            path = "vendor_setting"
        elif item.get("repository") and has_code_host:
            path = "automated"
        else:
            path = "manual"
        counts[path] += 1
        lane_id = "owner:" + (owner or "")
        lane = lanes.setdefault(lane_id, {"id": lane_id, "kind": "owner", "label": owner or "No owner named", "owner": owner,
                                          "assets": [], "automated": 0, "manual": 0, "vendor_setting": 0,
                                          "hands_on_hours": [0.0, 0.0, 0.0], "hands_on_basis": []})
        lane["assets"].append(key)
        lane[path] += 1
        if path in ("manual", "vendor_setting"):
            hours, basis, _ = (hands_on_hours(item.get("server_type") or "") if path == "manual"
                               else ((0.5, 1.0, 4.0), f"a {vendor['name']} setting", True))
            for i in range(3):
                lane["hands_on_hours"][i] += hours[i]
            if basis not in lane["hands_on_basis"]:
                lane["hands_on_basis"].append(basis)
            if basis.startswith("assumed"):
                note(assumptions, f"A manual change on a stack with no playbook takes {ASSUMED_HANDS_ON_HOURS[0]:g} to "
                                  f"{ASSUMED_HANDS_ON_HOURS[2]:g} hours of hands-on work.")

    out_lanes: List[Dict[str, Any]] = []
    any_assumed_response = False
    for lane in lanes.values():
        if lane["kind"] == "owner":
            resp, basis, measured = response_for(lane["owner"], response)
            any_assumed_response = any_assumed_response or not measured
            days = [resp[i] + lane["hands_on_hours"][i] / WORK_HOURS_PER_DAY for i in range(3)]
            parts = [f"response {basis}"]
            if lane["hands_on_hours"][2] > 0:
                parts.append(f"hands-on {lane['hands_on_hours'][1]:g} h ({'; '.join(lane['hands_on_basis'])})")
            if not lane["owner"]:
                days = [days[i] + UNOWNED_TRIAGE_DAYS[i] for i in range(3)]
                parts.append(f"plus {UNOWNED_TRIAGE_DAYS[0]:g}-{UNOWNED_TRIAGE_DAYS[2]:g} days to find an owner")
                note(gaps, f"{_assets(len(lane['assets']), 'affected asset')} {'has' if len(lane['assets']) == 1 else 'have'} no owner in the inventory.")
            out_lanes.append({"id": lane["id"], "kind": "owner", "label": lane["label"], "assets": len(lane["assets"]),
                              "asset_keys": lane["assets"][:50], "automated": lane["automated"], "manual": lane["manual"],
                              "vendor_setting": lane["vendor_setting"], "measured": measured,
                              "days": {"low": _r(days[0]), "likely": _r(days[1]), "high": _r(days[2])},
                              "basis": "; ".join(parts)})
        else:
            d = lane["days"]
            out_lanes.append({"id": lane["id"], "kind": "vendor_wait", "label": lane["label"], "assets": len(lane["assets"]),
                              "asset_keys": lane["assets"][:50], "measured": False,
                              "days": {"low": _r(d[0]), "likely": _r(d[1]), "high": _r(d[2])}, "basis": lane["basis"]})
    if any_assumed_response:
        note(assumptions, f"Where Morrow has no merged fix to measure, an owner takes {ASSUMED_RESPONSE_DAYS[0]:g} to "
                          f"{ASSUMED_RESPONSE_DAYS[2]:g} days to merge or apply a change ({ASSUMED_RESPONSE_DAYS[1]:g} likely).")
        if not response.get("samples"):
            note(gaps, "No fix has been merged through Morrow yet, so owner response times are assumed, not measured.")
    if unconfirmed:
        note(gaps, f"{_assets(unconfirmed, 'asset')} {'is' if unconfirmed == 1 else 'are'} counted as affected although the scan did not "
                   "record the exact key size.")
    if stale:
        note(gaps, f"{_assets(stale, 'affected asset')} {'was' if stale == 1 else 'were'} last scanned over {STALE_SCAN_DAYS} days ago "
                   "and may have changed.")

    out_lanes.sort(key=lambda lane: (-lane["days"]["likely"], -lane["days"]["high"], lane["label"]))
    if out_lanes:
        low = max(lane["days"]["low"] for lane in out_lanes)
        likely = max(lane["days"]["likely"] for lane in out_lanes)
        high = max(lane["days"]["high"] for lane in out_lanes)
    else:
        low = likely = high = 0.0
    if unscanned:
        # Never-scanned assets might depend on the algorithm too. They do not move the middle; they
        # widen the top as if every one were a manual change with no owner and no history.
        worst = (ASSUMED_RESPONSE_DAYS[2] + UNOWNED_TRIAGE_DAYS[2]
                 + unscanned * ASSUMED_HANDS_ON_HOURS[2] / WORK_HOURS_PER_DAY)
        high = max(high, min(worst, MAX_HIGH_DAYS))
        note(gaps, f"{_assets(unscanned, 'asset')} in the inventory {'has' if unscanned == 1 else 'have'} never been scanned; any could depend on "
                   f"{(plan.get('broken') or {}).get('name') or 'the algorithm'}. The upper end allows for that.")
        if worst > MAX_HIGH_DAYS:
            note(gaps, f"So many assets are unscanned that the upper end could be past {MAX_HIGH_DAYS:g} days.")
    return {
        "days": {"low": _r(low), "likely": _r(likely), "high": _r(high)},
        "affected": len(items), "paths": counts, "lanes": out_lanes,
        "slowest": out_lanes[0]["label"] if out_lanes else "",
        "assumptions": assumptions, "gaps": gaps,
        "model": ("Owners work in parallel. Each owner's lane is their response time, paid once, plus the hands-on "
                  "time of every change they apply by hand; pull requests the kill switch opens are reviewed together. "
                  "A vendor that does not offer the fallback is a lane of its own. Time-to-safe is the slowest lane."),
    }


def headline_days(days: Optional[Dict[str, float]]) -> Optional[int]:
    if not days:
        return None
    return int(math.ceil(float(days.get("likely") or 0.0)))


def _days_text(value: float) -> str:
    n = int(math.ceil(float(value)))
    return "under a day" if n <= 0 else f"{n} day" if n == 1 else f"{n} days"


def sentence(broken: str, fallback: str, est: Dict[str, Any]) -> str:
    """The one plain sentence the console leads with."""
    n = int(est.get("affected") or 0)
    if not n:
        return f"Nothing Morrow has scanned depends on {broken}, so a break this morning would need no move."
    days = est["days"]
    lo, hi = int(math.ceil(days["low"])), int(math.ceil(days["high"]))
    span = "" if lo == hi else f" (somewhere between {lo} and {hi} days)"
    what = "system that depends on it" if n == 1 else f"{n} systems that depend on it"
    return (f"If {broken} were broken this morning, the {what} would be on {fallback} in about "
            f"{_days_text(days['likely'])}{span}.")


# ── Storage ─────────────────────────────────────────────────────────────────────────────────────

_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS fire_drills (
        id TEXT PRIMARY KEY, org_id TEXT NOT NULL, broken TEXT NOT NULL, fallback TEXT NOT NULL DEFAULT '',
        trigger_kind TEXT NOT NULL DEFAULT 'manual', status TEXT NOT NULL, actor_id TEXT NOT NULL DEFAULT '',
        affected INTEGER NOT NULL DEFAULT 0, days_low REAL, days_likely REAL, days_high REAL,
        result_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL)""",
    "CREATE INDEX IF NOT EXISTS idx_fire_drills_org ON fire_drills(org_id, created_at)",
    """CREATE TABLE IF NOT EXISTS fire_drill_schedules (
        org_id TEXT PRIMARY KEY, cadence TEXT NOT NULL DEFAULT 'off', broken TEXT NOT NULL DEFAULT '',
        fallback TEXT NOT NULL DEFAULT '', next_run_at TEXT NOT NULL DEFAULT '', last_run_at TEXT NOT NULL DEFAULT '',
        last_error TEXT NOT NULL DEFAULT '', updated_by TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL)""",
)

_ready_lock = threading.Lock()
_ready_for = ""


def _init() -> None:
    global _ready_for
    from db_feature_store import dialect, _sqlite_path  # noqa: F401  (path changes between test databases)

    marker = f"{dialect()}:{_sqlite_path() if dialect() == 'sqlite' else ''}"
    if _ready_for == marker:
        return
    with _ready_lock:
        with feature_conn() as conn:
            for statement in _SCHEMA:
                conn.execute(statement)
            conn.commit()
        _ready_for = marker


def init_tables() -> None:
    """Create the tables now (db_postgres.apply_deferred_schemas, registered in app.py)."""
    global _ready_for
    _ready_for = ""
    _init()


def _drill_row(row: Any, full: bool = True) -> Dict[str, Any]:
    d = dict(row)
    result = json.loads(d.pop("result_json", "") or "{}")
    days = None if d.get("days_likely") is None else {"low": d.pop("days_low"), "likely": d.pop("days_likely"),
                                                      "high": d.pop("days_high")}
    for k in ("days_low", "days_likely", "days_high"):
        d.pop(k, None)
    d["trigger"] = d.pop("trigger_kind", "manual")
    d["days"] = days
    d["time_to_safe_days"] = headline_days(days)
    d["dry_run"] = True
    if full:
        d.update({k: v for k, v in result.items() if k not in d})
    return d


# ── Running a drill ─────────────────────────────────────────────────────────────────────────────

def _stored_policy(org_id: str) -> Dict[str, Any]:
    try:
        import db

        raw = str(db.get_integration_setting(f"org_policy_json::{org_id}", "") or "").strip()
        parsed = json.loads(raw) if raw else {}
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


#: app.py installs its own policy loader (defaults merged with the organization's saved policy).
POLICY_LOADER: Optional[Callable[[str], Dict[str, Any]]] = None


def _switch_history(org_id: str) -> List[Dict[str, Any]]:
    try:
        crypto_switch._init()
        with feature_conn() as conn:
            rows = conn.execute("SELECT asset_key, owner, opened_at, merged_at FROM crypto_switch_items "
                                "WHERE org_id = ? AND opened_at <> '' AND merged_at <> '' LIMIT 5000", (org_id,)).fetchall()
        return [dict(r) for r in rows]
    except Exception:
        return []


def gather(org_id: str) -> Dict[str, Any]:
    """Read the organization's inventory and remediation history (current tenant context). Reads only."""
    import db

    facts = db.latest_scan_facts_for_org(limit=5000)
    assets = db.list_assets(limit=5000)
    try:
        remediations = db.list_remediations(limit=2000)
    except Exception:
        remediations = []
    try:
        from services import code_hosts

        has_code_host = bool(code_hosts.has_connection(org_id))
    except Exception:
        has_code_host = False
    try:
        from services.advanced_pq_controls import list_crypto_mesh_profiles

        mesh = list_crypto_mesh_profiles(limit=1)
    except Exception:
        mesh = []
    policy = (POLICY_LOADER or _stored_policy)(org_id)
    return {"facts": facts, "assets": assets, "remediations": remediations, "switch_items": _switch_history(org_id),
            "has_code_host": has_code_host, "mesh_profiles": mesh, "policy": policy}


def compute(broken: str, fallback: str, data: Dict[str, Any], now: Optional[datetime] = None) -> Dict[str, Any]:
    """The whole drill result from gathered data. Pure (no writes, no network)."""
    now = now or _now_dt()
    spec = crypto_switch.resolve(broken)
    if not spec:
        raise DrillError(400, f"Unknown algorithm: {str(broken)[:60]!r}.")
    fallback = fallback or crypto_switch.default_fallback(spec["name"], data.get("mesh_profiles") or [])
    facts = list(data.get("facts") or [])
    assets = list(data.get("assets") or [])
    plan = crypto_switch.build_plan(spec["name"], fallback, facts, assets, policy=data.get("policy") or {})
    base = {"broken": spec["name"], "broken_kind": spec["kind"], "fallback": (plan.get("preflight") or {}).get("fallback", {}).get("name")
            or fallback, "scanned_assets": len(facts), "inventory_assets": len(assets)}
    if not plan["preflight"]["allowed"]:
        return {**base, "status": "blocked", "days": None, "affected": 0,
                "refusals": plan["preflight"]["refusals"], "warnings": plan["preflight"]["warnings"],
                "summary": "Your policy refuses the fallback, so the kill switch could not plan the move. Pick another "
                           "fallback or change the policy, then run the drill again."}
    if not facts:
        return {**base, "status": "no_data", "days": None, "affected": 0, "warnings": plan["preflight"]["warnings"],
                "summary": "Morrow has no scan of your systems yet, so there is nothing to time. Run a scan first."}
    owners = {str(a.get("asset_key") or ""): str(a.get("owner") or "") for a in assets}
    for f in facts:
        owners.setdefault(str(f.get("asset_key") or ""), str(f.get("owner") or ""))
    model = response_model(merge_samples(data.get("remediations") or [], data.get("switch_items") or [],
                                         lambda key: owners.get(key, "")))
    scanned = {str(f.get("asset_key") or "") for f in facts}
    unscanned = sum(1 for a in assets if str(a.get("asset_key") or "") not in scanned)
    cutoff = now - timedelta(days=STALE_SCAN_DAYS)
    stale = sum(1 for i in plan["items"] if (_ts(i.get("observed_at")) or now) < cutoff)
    est = estimate(plan, assets, has_code_host=bool(data.get("has_code_host")), response=model,
                   unscanned=unscanned, stale=stale)
    if not data.get("has_code_host") and est["paths"]["manual"]:
        est["gaps"].append("No code host is connected, so every change is counted as manual. Connecting one lets the "
                           "kill switch open pull requests.")
    return {**base, "status": "ok", **est, "summary": sentence(base["broken"], base["fallback"], est),
            "warnings": plan["preflight"]["warnings"],
            "response_samples": model["samples"], "unscanned_assets": unscanned,
            "by_priority": plan["summary"].get("by_priority") or {}}


def _cooldown(conn, org_id: str, now: datetime) -> None:
    row = conn.execute("SELECT created_at FROM fire_drills WHERE org_id = ? AND trigger_kind = 'manual' "
                       "ORDER BY created_at DESC LIMIT 1", (org_id,)).fetchone()
    last = _ts(dict(row)["created_at"]) if row else None
    if last and (now - last).total_seconds() < MANUAL_RUN_COOLDOWN_SECONDS:
        raise DrillError(429, "A drill just ran. Wait half a minute before running another.")


def run_drill(org_id: str, actor: Dict[str, str], broken: str, fallback: str = "", *, trigger: str = "manual",
              data: Optional[Dict[str, Any]] = None, now: Optional[datetime] = None) -> Dict[str, Any]:
    """Run one drill in dry run and store it. The only writes: the drill row and one audit entry."""
    _init()
    now = now or _now_dt()
    if trigger == "manual":
        with feature_conn() as conn:
            _cooldown(conn, org_id, now)
    data = gather(org_id) if data is None else data
    result = compute(broken, fallback, data, now)
    drill_id = "fdr_" + secrets.token_hex(8)
    days = result.get("days")
    stored = {k: v for k, v in result.items() if k not in ("broken", "fallback", "affected", "days", "status")}
    with feature_conn() as conn:
        conn.execute(
            "INSERT INTO fire_drills (id, org_id, broken, fallback, trigger_kind, status, actor_id, affected, days_low, "
            "days_likely, days_high, result_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (drill_id, org_id, result["broken"], str(result.get("fallback") or ""), trigger, result["status"],
             str(actor.get("actor_id") or ""), int(result.get("affected") or 0),
             days["low"] if days else None, days["likely"] if days else None, days["high"] if days else None,
             json.dumps(stored), _iso(now)))
        conn.commit()
    try:
        from db import append_audit_log

        append_audit_log(str(actor.get("actor_id") or ""), str(actor.get("actor_role") or ""), "fire_drill.run",
                         "fire_drill", drill_id, decision="allow",
                         details={"broken": result["broken"], "fallback": result.get("fallback"), "trigger": trigger,
                                  "status": result["status"], "affected": result.get("affected"), "days": days,
                                  "dry_run": True})
    except Exception:
        pass
    return get_drill(org_id, drill_id)


def get_drill(org_id: str, drill_id: str) -> Dict[str, Any]:
    _init()
    with feature_conn() as conn:
        row = conn.execute("SELECT * FROM fire_drills WHERE org_id = ? AND id = ?", (org_id, drill_id)).fetchone()
        if not row:
            raise DrillError(404, "Drill not found.")
        drill = _drill_row(row)
        drill["trend"] = _trend(conn, org_id, drill)
    return drill


def list_drills(org_id: str, limit: int = 20) -> List[Dict[str, Any]]:
    _init()
    with feature_conn() as conn:
        rows = conn.execute("SELECT * FROM fire_drills WHERE org_id = ? ORDER BY created_at DESC, id DESC LIMIT ?",
                            (org_id, max(1, min(int(limit or 20), 200)))).fetchall()
    return [_drill_row(r, full=False) for r in rows]


def _trend(conn, org_id: str, drill: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The earlier drill of the same algorithm to compare with: the newest one at least 60 days older
    ("last quarter"), else the one just before."""
    if drill.get("time_to_safe_days") is None:
        return None
    rows = conn.execute("SELECT * FROM fire_drills WHERE org_id = ? AND broken = ? AND created_at < ? AND days_likely IS NOT NULL "
                        "ORDER BY created_at DESC LIMIT 200", (org_id, drill["broken"], drill["created_at"])).fetchall()
    earlier = [_drill_row(r, full=False) for r in rows]
    if not earlier:
        return None
    at = _ts(drill["created_at"]) or _now_dt()
    quarter = next((d for d in earlier if 60 <= (at - (_ts(d["created_at"]) or at)).days <= 120), None)
    prev = quarter or earlier[0]
    now_days, prev_days = drill["time_to_safe_days"], prev["time_to_safe_days"]
    when = "last quarter" if quarter else "on " + str(prev["created_at"])[:10]
    if now_days < prev_days:
        direction, label = "down", f"down from {prev_days} {'day' if prev_days == 1 else 'days'} {when}"
    elif now_days > prev_days:
        direction, label = "up", f"up from {prev_days} {'day' if prev_days == 1 else 'days'} {when}"
    else:
        direction, label = "same", f"the same as {when}"
    return {"previous_days": prev_days, "previous_at": prev["created_at"], "previous_id": prev["id"],
            "direction": direction, "label": label}


# ── Schedule ────────────────────────────────────────────────────────────────────────────────────

def _add_months(value: datetime, months: int) -> datetime:
    month = value.month - 1 + months
    year, month = value.year + month // 12, month % 12 + 1
    day = min(value.day, [31, 29 if year % 4 == 0 and (year % 100 or year % 400 == 0) else 28, 31, 30, 31, 30,
                          31, 31, 30, 31, 30, 31][month - 1])
    return value.replace(year=year, month=month, day=day)


def get_schedule(org_id: str) -> Dict[str, Any]:
    _init()
    with feature_conn() as conn:
        row = conn.execute("SELECT * FROM fire_drill_schedules WHERE org_id = ?", (org_id,)).fetchone()
    if not row:
        return {"cadence": "off", "broken": DEFAULT_ALGORITHM, "fallback": "", "next_run_at": "", "last_run_at": ""}
    d = dict(row)
    d.pop("org_id", None)
    return d


def set_schedule(org_id: str, actor: Dict[str, str], cadence: str, broken: str = "", fallback: str = "",
                 now: Optional[datetime] = None) -> Dict[str, Any]:
    _init()
    cadence = str(cadence or "").strip().lower()
    if cadence not in CADENCES:
        raise DrillError(400, "Cadence must be off, monthly or quarterly.")
    spec = crypto_switch.resolve(broken or DEFAULT_ALGORITHM)
    if not spec:
        raise DrillError(400, f"Unknown algorithm: {str(broken)[:60]!r}.")
    if fallback and not crypto_switch.resolve(fallback):
        raise DrillError(400, f"Unknown fallback: {str(fallback)[:60]!r}.")
    now = now or _now_dt()
    next_run = _iso(_add_months(now, CADENCES[cadence])) if CADENCES[cadence] else ""
    with feature_conn() as conn:
        conn.execute("DELETE FROM fire_drill_schedules WHERE org_id = ?", (org_id,))
        conn.execute("INSERT INTO fire_drill_schedules (org_id, cadence, broken, fallback, next_run_at, last_run_at, last_error, "
                     "updated_by, updated_at) VALUES (?, ?, ?, ?, ?, '', '', ?, ?)",
                     (org_id, cadence, spec["name"], str(fallback or ""), next_run, str(actor.get("actor_id") or ""), _iso(now)))
        conn.commit()
    try:
        from db import append_audit_log

        append_audit_log(str(actor.get("actor_id") or ""), str(actor.get("actor_role") or ""), "fire_drill.schedule",
                         "fire_drill_schedule", org_id, decision="allow",
                         details={"cadence": cadence, "broken": spec["name"], "fallback": fallback or ""})
    except Exception:
        pass
    return get_schedule(org_id)


def run_due(now: Optional[datetime] = None, limit: int = 20,
            runner: Optional[Callable[..., Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Celery beat entry point (tasks.py, hourly): run every scheduled drill that is due."""
    from services.tenant_scope import platform_scope

    import db

    _init()
    now = now or _now_dt()
    runner = runner or run_drill
    with platform_scope("fire drill: scheduled drills picked across tenants"), feature_conn() as conn:
        due = [dict(r) for r in conn.execute(
            "SELECT org_id, cadence, broken, fallback FROM fire_drill_schedules WHERE cadence <> 'off' AND next_run_at <> '' "
            "AND next_run_at <= ? ORDER BY next_run_at LIMIT ?", (_iso(now), int(limit))).fetchall()]
    results = []
    for row in due:
        org_id = row["org_id"]
        token = db.set_current_organization_id(org_id)
        error = ""
        try:
            drill = runner(org_id, {"actor_id": "scheduler", "actor_role": "system"}, row["broken"], row["fallback"],
                           trigger="scheduled", now=now)
            results.append({"org_id": org_id, "ok": True, "id": drill.get("id")})
        except Exception as exc:  # one tenant's failure must not stop the others
            error = str(getattr(exc, "detail", "") or exc.__class__.__name__)[:300]
            results.append({"org_id": org_id, "ok": False, "error": error})
        finally:
            months = CADENCES.get(row["cadence"], 0) or 1
            with feature_conn() as conn:
                conn.execute("UPDATE fire_drill_schedules SET next_run_at = ?, last_run_at = ?, last_error = ? WHERE org_id = ?",
                             (_iso(_add_months(now, months)), _iso(now), error, org_id))
                conn.commit()
            db.reset_current_organization_id(token)
    return {"due": len(due), "results": results}


def overview(org_id: str) -> Dict[str, Any]:
    history = list_drills(org_id, limit=12)
    latest = get_drill(org_id, history[0]["id"]) if history else None
    return {"latest": latest, "history": history, "schedule": get_schedule(org_id),
            "algorithms": DRILL_ALGORITHMS, "cadences": list(CADENCES)}


if __name__ == "__main__":  # pragma: no cover - for a deployment without a Celery worker
    import sys

    if "--due" in sys.argv:
        print(json.dumps(run_due(), indent=2))
