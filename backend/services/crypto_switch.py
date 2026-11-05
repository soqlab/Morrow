"""Crypto kill switch: "algorithm or group X is broken, switch to fallback Y".

An org admin declares the break. Morrow then builds an incident plan from its own inventory (the
newest scan of every asset joined with the asset's owner, criticality, environment and data
lifetime): every asset that still uses X, its owner, a priority score, and the exact configuration
or code change for that asset's stack (the same snippet generator the migration autopilot uses),
grouped into batches in priority order.

Nothing touches a live system. The plan starts in dry-run, must be approved by an admin, and each
batch is opened by an admin as pull requests on the organization's connected code host (or, for an
asset with no repository, handed over as a configuration the customer applies). Morrow then tracks
each request, asks for a rescan once it is merged, and marks the asset switched only when a newer
scan observes the fallback algorithm. Every step is written to the audit journal.

Pre-flight refuses a fallback that is itself weaker than the organization's policy allows.
"""

from __future__ import annotations

import json
import re
import secrets
import threading
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from db_feature_store import feature_conn

# ── Algorithm catalogue ─────────────────────────────────────────────────────────────────────────
# kind: "kex" (TLS key-exchange group) or "sig" (certificate / signature key).
# bits: classical security strength in bits (NIST SP 800-57 style), used for the policy floor.

ALGORITHMS: Dict[str, Dict[str, Any]] = {
    "X25519MLKEM768":     {"kind": "kex", "family": "mlkem", "pq": True, "bits": 128, "names": ["x25519mlkem768", "x25519kyber768", "x25519kyber768draft00"]},
    "SecP256r1MLKEM768":  {"kind": "kex", "family": "mlkem", "pq": True, "bits": 128, "names": ["secp256r1mlkem768", "p256mlkem768"]},
    "SecP384r1MLKEM1024": {"kind": "kex", "family": "mlkem", "pq": True, "bits": 192, "names": ["secp384r1mlkem1024", "p384mlkem1024"]},
    "MLKEM768":           {"kind": "kex", "family": "mlkem", "pq": True, "bits": 192, "names": ["mlkem768", "kyber768"]},
    "MLKEM1024":          {"kind": "kex", "family": "mlkem", "pq": True, "bits": 256, "names": ["mlkem1024", "kyber1024"]},
    "X25519":             {"kind": "kex", "family": "ecdh", "pq": False, "bits": 128, "names": ["x25519", "curve25519", "ecdhx25519"]},
    "X448":               {"kind": "kex", "family": "ecdh", "pq": False, "bits": 224, "names": ["x448", "curve448"]},
    "P-256":              {"kind": "kex", "family": "ecdh", "pq": False, "bits": 128, "names": ["p256", "secp256r1", "prime256v1", "ecdhp256"]},
    "P-384":              {"kind": "kex", "family": "ecdh", "pq": False, "bits": 192, "names": ["p384", "secp384r1", "ecdhp384"]},
    "FFDHE2048":          {"kind": "kex", "family": "ffdh", "pq": False, "bits": 112, "names": ["ffdhe2048", "dh2048"]},
    "FFDHE1024":          {"kind": "kex", "family": "ffdh", "pq": False, "bits": 80, "names": ["ffdhe1024", "dh1024"]},
    "RSA-1024":   {"kind": "sig", "family": "rsa", "pq": False, "bits": 80, "key_bits": 1024, "names": ["rsa1024"]},
    "RSA-2048":   {"kind": "sig", "family": "rsa", "pq": False, "bits": 112, "key_bits": 2048, "names": ["rsa2048"]},
    "RSA-3072":   {"kind": "sig", "family": "rsa", "pq": False, "bits": 128, "key_bits": 3072, "names": ["rsa3072"]},
    "RSA-4096":   {"kind": "sig", "family": "rsa", "pq": False, "bits": 152, "key_bits": 4096, "names": ["rsa4096"]},
    "ECDSA-P256": {"kind": "sig", "family": "ec", "pq": False, "bits": 128, "curve": "p256", "names": ["ecdsap256", "ecdsasecp256r1", "ecp256"]},
    "ECDSA-P384": {"kind": "sig", "family": "ec", "pq": False, "bits": 192, "curve": "p384", "names": ["ecdsap384", "ecdsasecp384r1", "ecp384"]},
    "Ed25519":    {"kind": "sig", "family": "ed25519", "pq": False, "bits": 128, "names": ["ed25519"]},
    "ML-DSA-44":  {"kind": "sig", "family": "mldsa", "pq": True, "bits": 128, "names": ["mldsa44", "dilithium2"]},
    "ML-DSA-65":  {"kind": "sig", "family": "mldsa", "pq": True, "bits": 192, "names": ["mldsa65", "dilithium3"]},
    "ML-DSA-87":  {"kind": "sig", "family": "mldsa", "pq": True, "bits": 256, "names": ["mldsa87", "dilithium5"]},
    "SLH-DSA-SHA2-128s": {"kind": "sig", "family": "slhdsa", "pq": True, "bits": 128, "names": ["slhdsasha2128s", "slhdsa128s", "sphincs128s"]},
}

# A group names a whole family; as a fallback it means its default member.
GROUPS: Dict[str, Dict[str, Any]] = {
    "ML-KEM": {"kind": "kex", "families": ["mlkem"], "default": "X25519MLKEM768", "names": ["mlkem", "mlkemhybrid", "kyber", "hybridmlkem", "pqhybrid"]},
    "ECDH":   {"kind": "kex", "families": ["ecdh"], "default": "X25519", "names": ["ecdh", "ecdhe", "classicalecdh"]},
    "FFDH":   {"kind": "kex", "families": ["ffdh"], "default": "FFDHE2048", "names": ["ffdh", "dh", "dhe"]},
    "RSA":    {"kind": "sig", "families": ["rsa"], "default": "RSA-3072", "names": ["rsa"]},
    "ECDSA":  {"kind": "sig", "families": ["ec"], "default": "ECDSA-P256", "names": ["ecdsa", "ecc", "ec"]},
    "ML-DSA": {"kind": "sig", "families": ["mldsa"], "default": "ML-DSA-65", "names": ["mldsa", "dilithium"]},
    "SLH-DSA": {"kind": "sig", "families": ["slhdsa"], "default": "SLH-DSA-SHA2-128s", "names": ["slhdsa", "sphincs"]},
}

HARD_FLOOR_BITS = 112  # below this no policy can allow a fallback (RSA-1024, FFDHE1024).

ITEM_STATES = ("vulnerable", "pr_open", "merged", "switched", "rescan_mismatch", "manual_apply", "failed")


class SwitchError(Exception):
    def __init__(self, status_code: int, detail: Any):
        super().__init__(str(detail))
        self.status_code = status_code
        self.detail = detail


def _norm(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value or "").lower())


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _ts(value: Any) -> Optional[datetime]:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00").replace(" ", "T"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _after(value: Any, since: Any) -> bool:
    """True when timestamp `value` is strictly later than `since` (any ISO-8601 spelling)."""
    a, b = _ts(value), _ts(since)
    if a is None:
        return False
    return b is None or a > b


def resolve(name: Any) -> Optional[Dict[str, Any]]:
    """A concrete algorithm or a group, from any common spelling. None when unknown."""
    key = _norm(name)
    if not key:
        return None
    for canon, info in ALGORITHMS.items():
        if key == _norm(canon) or key in info["names"]:
            return {"name": canon, "group": False, **info}
    for canon, info in GROUPS.items():
        if key == _norm(canon) or key in info["names"]:
            return {"name": canon, "group": True, **info}
    return None


def catalogue() -> Dict[str, Any]:
    return {
        "algorithms": [{"name": k, "kind": v["kind"], "family": v["family"], "post_quantum": v["pq"], "security_bits": v["bits"]}
                       for k, v in ALGORITHMS.items()],
        "groups": [{"name": k, "kind": v["kind"], "default_member": v["default"]} for k, v in GROUPS.items()],
    }


# ── Matching scan observations ──────────────────────────────────────────────────────────────────

def observed(fact: Dict[str, Any], kind: str) -> Tuple[str, str]:
    """(family, concrete algorithm or "") that the scan observed for this kind."""
    if kind == "kex":
        raw = _norm(fact.get("key_exchange"))
        if not raw:
            return "", ""
        for canon, info in ALGORITHMS.items():
            if info["kind"] == "kex" and (raw == _norm(canon) or raw in info["names"]):
                return info["family"], canon
        if "mlkem" in raw or "kyber" in raw:
            return "mlkem", ""
        if raw.startswith("ffdhe") or raw.startswith("dh"):
            return "ffdh", ""
        if raw.startswith(("x25519", "x448", "secp", "prime", "p256", "p384", "p521", "ecdh")):
            return "ecdh", ""
        return "", ""
    key_type = _norm(fact.get("key_type"))
    sig = _norm(fact.get("sig_algorithm"))
    bits = int(fact.get("key_bits") or 0)
    curve = _norm(fact.get("key_curve"))
    for fam, tokens in (("mldsa", ("mldsa", "dilithium")), ("slhdsa", ("slhdsa", "sphincs"))):
        if any(t in key_type or t in sig for t in tokens):
            for canon, info in ALGORITHMS.items():
                if info["family"] == fam and any(n in key_type or n in sig for n in info["names"]):
                    return fam, canon
            return fam, ""
    if "rsa" in key_type:
        for canon, info in ALGORITHMS.items():
            if info["family"] == "rsa" and info.get("key_bits") == bits:
                return "rsa", canon
        return "rsa", ""
    if "ed25519" in key_type:
        return "ed25519", "Ed25519"
    if key_type in ("ec", "ecc", "ecdsa") or key_type.startswith("ec"):
        if curve in ("p256", "secp256r1", "prime256v1"):
            return "ec", "ECDSA-P256"
        if curve in ("p384", "secp384r1"):
            return "ec", "ECDSA-P384"
        return "ec", ""
    return "", ""


def covers(spec: Dict[str, Any], family: str, concrete: str) -> Tuple[bool, bool]:
    """(affected, confirmed). An observation of the right family whose exact size the scan did not
    record is affected but unconfirmed: in an emergency it is planned, and flagged."""
    if not family:
        return False, False
    if spec["group"]:
        return family in spec["families"], True
    if concrete:
        return concrete == spec["name"], True
    return family == spec["family"], False


def is_switched(fallback: Dict[str, Any], broken: Dict[str, Any], fact: Dict[str, Any]) -> bool:
    family, concrete = observed(fact, fallback["kind"])
    if covers(broken, family, concrete)[0] and concrete != fallback["name"]:
        return False
    if concrete:
        return concrete == fallback["name"]
    return bool(family) and family == fallback["family"] and fallback["pq"]


# ── Policy pre-flight ───────────────────────────────────────────────────────────────────────────

def _regions(asset: Dict[str, Any]) -> set:
    out = set()
    meta = asset.get("metadata") if isinstance(asset.get("metadata"), dict) else {}
    for value in [meta.get("region"), meta.get("regions"), asset.get("environment")] + list(asset.get("tags") or []):
        for part in (value if isinstance(value, list) else [value]):
            text = str(part or "").strip().lower()
            if text:
                out.add(text)
                out.update(t for t in re.split(r"[^a-z0-9]+", text) if t)
    return out


def preflight(broken_name: Any, fallback_name: Any, policy: Optional[Dict[str, Any]] = None,
              assets: Iterable[Dict[str, Any]] = ()) -> Dict[str, Any]:
    """Can fallback_name replace broken_name under this organization's policy? Never raises."""
    policy = dict(policy or {})
    refusals: List[str] = []
    warnings: List[str] = []
    broken = resolve(broken_name)
    fallback = resolve(fallback_name)
    if not broken:
        refusals.append(f"Unknown algorithm or group: {str(broken_name)[:60]!r}.")
    if not fallback:
        refusals.append(f"Unknown fallback algorithm: {str(fallback_name)[:60]!r}.")
    if broken and fallback:
        if fallback["group"]:
            fallback = resolve(fallback["default"]) or fallback
        if fallback["kind"] != broken["kind"]:
            what = {"kex": "a key-exchange group", "sig": "a certificate/signature algorithm"}
            refusals.append(f"{broken['name']} is {what[broken['kind']]} but {fallback['name']} is {what[fallback['kind']]}; "
                            "the fallback must replace like with like.")
        elif covers(broken, fallback["family"], fallback["name"])[0]:
            refusals.append(f"{fallback['name']} is itself covered by the declared break ({broken['name']}).")
        floor = max(HARD_FLOOR_BITS, int(policy.get("kill_switch_min_security_bits") or 112))
        if fallback["bits"] < floor:
            refusals.append(f"{fallback['name']} gives {fallback['bits']}-bit security; policy requires at least {floor}.")
        forbidden = {_norm(x) for x in policy.get("kill_switch_forbidden_fallbacks") or []}
        if _norm(fallback["name"]) in forbidden or forbidden.intersection(fallback.get("names") or []):
            refusals.append(f"Organization policy forbids {fallback['name']} as a fallback.")
        if fallback["family"] == "rsa":
            for item in policy.get("allowed_keys") or []:
                text = str(item or "").upper().replace(" ", "")
                if text.startswith("RSA>="):
                    try:
                        need = int(text.split(">=", 1)[1])
                    except ValueError:
                        continue
                    if int(fallback.get("key_bits") or 0) < need:
                        refusals.append(f"Organization policy allows RSA keys of {need} bits or more; {fallback['name']} is smaller.")
        if not fallback["pq"]:
            if policy.get("kill_switch_require_quantum_safe_fallback"):
                refusals.append(f"Organization policy requires a quantum-safe fallback; {fallback['name']} is not.")
            elif broken.get("pq") or (broken["group"] and any(ALGORITHMS[a]["pq"] for a in ALGORITHMS
                                                               if ALGORITHMS[a]["family"] in broken["families"])):
                if policy.get("kill_switch_allow_classical_fallback") is False:
                    refusals.append("Organization policy does not allow a classical (quantum-vulnerable) fallback.")
                else:
                    warnings.append(f"{fallback['name']} is classical: traffic recorded while it is in use is exposed to "
                                    "harvest-now-decrypt-later. Keep the switch temporary and plan the return.")
        asset_regions = set()
        for asset in assets or []:
            asset_regions |= _regions(asset)
        for rule in policy.get("banned_crypto_rules") or []:
            if not isinstance(rule, dict):
                continue
            banned = {_norm(a) for a in rule.get("algorithms") or []}
            if not (_norm(fallback["name"]) in banned or banned.intersection(fallback.get("names") or [])):
                continue
            regions = {str(r).strip().lower() for r in rule.get("regions") or [] if str(r).strip()}
            if not regions or regions & asset_regions:
                refusals.append(str(rule.get("message") or f"Organization policy bans {fallback['name']}.")
                                + f" (policy rule {rule.get('id') or 'banned_crypto_rules'})")
    return {
        "allowed": not refusals,
        "refusals": refusals,
        "warnings": warnings,
        "broken": _public_alg(broken),
        "fallback": _public_alg(fallback),
    }


def _public_alg(spec: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not spec:
        return None
    out = {"name": spec["name"], "kind": spec["kind"], "group": spec["group"]}
    if not spec["group"]:
        out.update(post_quantum=spec["pq"], security_bits=spec["bits"], family=spec["family"])
    else:
        out["families"] = spec["families"]
    return out


def default_fallback(broken_name: Any, mesh_profiles: Iterable[Dict[str, Any]] = ()) -> str:
    """Builds on the crypto-mesh profile's emergency_algorithm (services/advanced_pq_controls).

    The newest saved mesh profile names a preferred group (its emergency_algorithm, first in
    primary_profile.tls_groups) and a classical break-glass fallback. If the preferred group is what
    broke, the break-glass group is the fallback; otherwise the preferred group is.
    """
    broken = resolve(broken_name)
    for row in mesh_profiles or []:
        profile = row.get("profile") if isinstance(row.get("profile"), dict) else row
        groups = list(((profile or {}).get("primary_profile") or {}).get("tls_groups") or [])
        candidates = groups + [g for c in (profile or {}).get("contingency_profiles") or [] for g in c.get("groups") or []]
        for name in candidates:
            spec = resolve(name)
            if spec and broken and spec["kind"] == broken["kind"] and not covers(broken, spec["family"], spec["name"])[0]:
                return spec["name"]
        break
    if broken and broken["kind"] == "kex":
        return "X25519" if (broken.get("pq") or "mlkem" in broken.get("families", [])) else "X25519MLKEM768"
    if broken and broken["kind"] == "sig":
        return "ML-DSA-65"
    return ""


# ── Priority ────────────────────────────────────────────────────────────────────────────────────

_CRITICALITY = {"critical": 40, "high": 30, "medium": 20, "moderate": 20, "low": 10}
_PUBLIC_TAGS = ("internet", "public", "external", "edge", "customer-facing", "dmz")


def _lifetime_years(value: Any) -> Optional[float]:
    text = str(value or "").strip().lower()
    if not text:
        return None
    if text in ("long", "long-term", "permanent", "forever", "decades"):
        return 25.0
    if text in ("medium", "years"):
        return 5.0
    if text in ("short", "ephemeral", "days", "session"):
        return 0.1
    match = re.search(r"(\d+(?:\.\d+)?)\s*(y|yr|year|m|mo|month|d|day)?", text)
    if not match:
        return None
    number, unit = float(match.group(1)), (match.group(2) or "y")
    if unit.startswith("mo") or unit == "m":
        return number / 12.0
    if unit.startswith("d"):
        return number / 365.0
    return number


def priority(asset: Dict[str, Any], fact: Dict[str, Any]) -> Dict[str, Any]:
    """Score 0-100 from criticality, exposure and how long the protected data must stay secret."""
    crit_text = str(asset.get("criticality") or fact.get("criticality") or "").strip().lower()
    crit = _CRITICALITY.get(crit_text, 15)
    env = str(asset.get("environment") or fact.get("environment") or "").strip().lower()
    tags = [str(t).lower() for t in asset.get("tags") or []]
    meta = asset.get("metadata") if isinstance(asset.get("metadata"), dict) else {}
    public = bool(meta.get("internet_facing")) or any(any(p in t for p in _PUBLIC_TAGS) for t in tags)
    if env in ("prod", "production", "live"):
        exposure = 20
    elif env in ("staging", "stage", "uat", "preprod"):
        exposure = 8
    elif env in ("dev", "development", "test", "sandbox", "lab"):
        exposure = 3
    else:
        exposure = 10
    if public:
        exposure += 15
    years = _lifetime_years(asset.get("confidentiality_lifetime") or meta.get("data_lifetime"))
    if years is None:
        lifetime = 10
    elif years >= 10:
        lifetime = 30
    elif years >= 5:
        lifetime = 22
    elif years >= 2:
        lifetime = 12
    else:
        lifetime = 5
    score = min(100, crit + exposure + lifetime)
    tier = "p0" if score >= 75 else "p1" if score >= 55 else "p2" if score >= 35 else "p3"
    return {"score": score, "tier": tier, "criticality": crit_text or "unknown", "environment": env or "unknown",
            "internet_facing": public, "data_lifetime_years": years}


def server_type_for(asset: Dict[str, Any], fact: Dict[str, Any]) -> str:
    from services import migration_autopilot

    meta = asset.get("metadata") if isinstance(asset.get("metadata"), dict) else {}
    for value in (meta.get("server_type"), meta.get("stack"), meta.get("tls_terminator"), meta.get("language")):
        text = str(value or "").strip().lower()
        if text in migration_autopilot.SNIPPET_SERVER_TYPES:
            return text
        if text in ("golang",):
            return "go"
        if text in ("jvm", "kotlin", "spring"):
            return "java"
    for tag in asset.get("tags") or []:
        text = str(tag or "").strip().lower()
        if text in migration_autopilot.SNIPPET_SERVER_TYPES:
            return text
    key = str(asset.get("asset_key") or fact.get("asset_key") or "")
    host, _, port = key.rpartition(":")
    return migration_autopilot._infer_server_type({"host": host, "port": int(port) if port.isdigit() else 443,
                                                    "server": meta.get("server") or meta.get("server_header") or ""})


def change_for(server_type: str, broken: Dict[str, Any], fallback: Dict[str, Any], asset_key: str,
               incident_id: str) -> Dict[str, str]:
    from services import migration_autopilot

    title = f"Crypto kill switch: {broken['name']} -> {fallback['name']}"
    if fallback["kind"] == "kex":
        groups = [fallback["name"]]
        # A hybrid fallback keeps a classical group behind it for clients that lack the hybrid.
        if fallback["pq"] and fallback["name"].startswith("X25519") and not covers(broken, "ecdh", "X25519")[0]:
            groups.append("X25519")
        content = migration_autopilot.build_tls_snippet(server_type, groups=groups, asset_key=asset_key, title=title)
    else:
        content = migration_autopilot.build_tls_snippet(server_type, signature=fallback["name"], asset_key=asset_key, title=title)
    slug = re.sub(r"[^a-z0-9]+", "-", asset_key.lower()).strip("-")[:60] or "endpoint"
    path = f"morrow/crypto-switch/{incident_id[-8:].lower()}/{server_type}-{slug}.{migration_autopilot.snippet_extension(server_type)}"
    return {"path": path, "content": content, "howto": migration_autopilot.snippet_howto(server_type, path, asset_key)}


# ── Plan building (pure) ────────────────────────────────────────────────────────────────────────

def build_plan(broken_name: str, fallback_name: str, facts: Iterable[Dict[str, Any]], assets: Iterable[Dict[str, Any]],
               *, batch_size: int = 10, incident_id: str = "preview", policy: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The incident plan: affected assets in priority order, with owner, change and batch."""
    assets_by_key = {str(a.get("asset_key") or ""): a for a in assets or []}
    facts = list(facts or [])
    check = preflight(broken_name, fallback_name, policy, assets=[assets_by_key.get(str(f.get("asset_key")), f) for f in facts])
    if not check["allowed"]:
        return {"preflight": check, "items": [], "batches": [], "summary": {"affected": 0}}
    broken = resolve(broken_name)
    fallback = resolve(check["fallback"]["name"])
    items: List[Dict[str, Any]] = []
    for fact in facts:
        key = str(fact.get("asset_key") or "").strip()
        if not key:
            continue
        family, concrete = observed(fact, broken["kind"])
        hit, confirmed = covers(broken, family, concrete)
        if not hit:
            continue
        asset = assets_by_key.get(key) or {"asset_key": key}
        prio = priority(asset, fact)
        stype = server_type_for({**asset, "asset_key": key}, fact)
        change = change_for(stype, broken, fallback, key, incident_id)
        host, _, port = key.rpartition(":")
        items.append({
            "asset_key": key, "host": host or key, "port": int(port) if port.isdigit() else 443,
            "owner": str(asset.get("owner") or fact.get("owner") or ""), "team": str(asset.get("team") or fact.get("team") or ""),
            "priority_score": prio["score"], "priority": prio["tier"], "priority_factors": prio,
            "server_type": stype, "observed": concrete or family, "observed_confirmed": confirmed,
            "observed_scan_id": str(fact.get("scan_id") or ""), "observed_at": str(fact.get("scanned_at") or ""),
            "repository": str(asset.get("repository_name") or ""),
            "change_path": change["path"], "change_content": change["content"], "change_howto": change["howto"],
        })
    items.sort(key=lambda i: (-i["priority_score"], i["asset_key"]))
    size = max(1, min(int(batch_size or 10), 200))
    for rank, item in enumerate(items):
        item["rank"] = rank + 1
        item["batch"] = rank // size + 1
    batches = [{"batch": b, "assets": [i["asset_key"] for i in items if i["batch"] == b]}
               for b in sorted({i["batch"] for i in items})]
    by_tier: Dict[str, int] = {}
    for item in items:
        by_tier[item["priority"]] = by_tier.get(item["priority"], 0) + 1
    return {"preflight": check, "broken": check["broken"], "fallback": check["fallback"], "items": items,
            "batches": batches, "summary": {"affected": len(items), "batches": len(batches), "by_priority": by_tier,
                                            "unowned": sum(1 for i in items if not i["owner"]),
                                            "no_repository": sum(1 for i in items if not i["repository"])}}


# ── Storage ─────────────────────────────────────────────────────────────────────────────────────

_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS crypto_switch_incidents (
        id TEXT PRIMARY KEY, org_id TEXT NOT NULL, broken TEXT NOT NULL, fallback TEXT NOT NULL,
        kind TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '', status TEXT NOT NULL, dry_run INTEGER NOT NULL DEFAULT 1,
        batch_size INTEGER NOT NULL DEFAULT 10, repository TEXT NOT NULL DEFAULT '', connection_id TEXT NOT NULL DEFAULT '',
        base_branch TEXT NOT NULL DEFAULT '', preflight_json TEXT NOT NULL DEFAULT '{}', events_json TEXT NOT NULL DEFAULT '[]',
        created_by TEXT NOT NULL DEFAULT '', approved_by TEXT NOT NULL DEFAULT '', approved_at TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL)""",
    "CREATE INDEX IF NOT EXISTS idx_crypto_switch_incidents_org ON crypto_switch_incidents(org_id, created_at)",
    """CREATE TABLE IF NOT EXISTS crypto_switch_items (
        id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, org_id TEXT NOT NULL, asset_key TEXT NOT NULL,
        owner TEXT NOT NULL DEFAULT '', team TEXT NOT NULL DEFAULT '', priority_score REAL NOT NULL DEFAULT 0,
        priority TEXT NOT NULL DEFAULT 'p3', rank INTEGER NOT NULL DEFAULT 0, batch INTEGER NOT NULL DEFAULT 1,
        server_type TEXT NOT NULL DEFAULT 'nginx', observed TEXT NOT NULL DEFAULT '', factors_json TEXT NOT NULL DEFAULT '{}',
        repository TEXT NOT NULL DEFAULT '', change_path TEXT NOT NULL DEFAULT '', change_content TEXT NOT NULL DEFAULT '',
        change_howto TEXT NOT NULL DEFAULT '', state TEXT NOT NULL DEFAULT 'vulnerable', pr_url TEXT NOT NULL DEFAULT '',
        pr_number TEXT NOT NULL DEFAULT '', connection_id TEXT NOT NULL DEFAULT '', opened_at TEXT NOT NULL DEFAULT '',
        merged_at TEXT NOT NULL DEFAULT '', rescan_scan_id TEXT NOT NULL DEFAULT '', rescan_requested_at TEXT NOT NULL DEFAULT '',
        verified_scan_id TEXT NOT NULL DEFAULT '', verified_at TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL)""",
    "CREATE INDEX IF NOT EXISTS idx_crypto_switch_items_incident ON crypto_switch_items(org_id, incident_id, batch)",
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


def _incident_row(row: Any) -> Dict[str, Any]:
    d = dict(row)
    d["dry_run"] = bool(int(d.get("dry_run") or 0))
    d["preflight"] = json.loads(d.pop("preflight_json", "") or "{}")
    d["events"] = json.loads(d.pop("events_json", "") or "[]")
    return d


def _item_row(row: Any, with_change: bool = False) -> Dict[str, Any]:
    d = dict(row)
    d["priority_factors"] = json.loads(d.pop("factors_json", "") or "{}")
    if not with_change:
        d.pop("change_content", None)
    return d


def _get_incident(conn, org_id: str, incident_id: str) -> Dict[str, Any]:
    row = conn.execute("SELECT * FROM crypto_switch_incidents WHERE org_id = ? AND id = ?", (org_id, incident_id)).fetchone()
    if not row:
        raise SwitchError(404, "Incident not found.")
    return _incident_row(row)


def _append_event(conn, org_id: str, incident: Dict[str, Any], actor: str, action: str, details: Dict[str, Any]) -> None:
    events = list(incident.get("events") or [])[-199:]
    events.append({"at": _now(), "actor": actor, "action": action, **details})
    incident["events"] = events
    conn.execute("UPDATE crypto_switch_incidents SET events_json = ?, updated_at = ? WHERE org_id = ? AND id = ?",
                 (json.dumps(events), _now(), org_id, incident["id"]))


def _journal(actor: Dict[str, str], action: str, incident_id: str, details: Dict[str, Any]) -> None:
    """The tamper-evident audit log (db.append_audit_log) for every step."""
    from db import append_audit_log

    append_audit_log(str(actor.get("actor_id") or ""), str(actor.get("actor_role") or ""), action,
                     "crypto_switch_incident", incident_id, decision="allow", details=details)


def _notify(event_type: str, payload: Dict[str, Any]) -> None:
    try:
        from events import emit_platform_event

        emit_platform_event(event_type, payload)
    except Exception:
        pass


# ── Incident lifecycle ──────────────────────────────────────────────────────────────────────────

def create_incident(org_id: str, actor: Dict[str, str], broken: str, fallback: str, *, facts, assets,
                    policy: Optional[Dict[str, Any]] = None, reason: str = "", dry_run: bool = True,
                    batch_size: int = 10, repository: str = "", connection_id: str = "", base_branch: str = "") -> Dict[str, Any]:
    _init()
    incident_id = "ksw_" + secrets.token_hex(8)
    plan = build_plan(broken, fallback, facts, assets, batch_size=batch_size, incident_id=incident_id, policy=policy)
    if not plan["preflight"]["allowed"]:
        _journal(actor, "crypto_switch.preflight_refused", incident_id,
                 {"broken": broken, "fallback": fallback, "refusals": plan["preflight"]["refusals"]})
        raise SwitchError(400, {"message": "Pre-flight refused the fallback.", "refusals": plan["preflight"]["refusals"],
                                "preflight": plan["preflight"]})
    now = _now()
    actor_id = str(actor.get("actor_id") or "")
    with feature_conn() as conn:
        conn.execute(
            "INSERT INTO crypto_switch_incidents (id, org_id, broken, fallback, kind, reason, status, dry_run, batch_size, "
            "repository, connection_id, base_branch, preflight_json, events_json, created_by, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, 'planned', ?, ?, ?, ?, ?, ?, '[]', ?, ?, ?)",
            (incident_id, org_id, plan["broken"]["name"], plan["fallback"]["name"], plan["broken"]["kind"], str(reason or "")[:2000],
             1 if dry_run else 0, int(batch_size or 10), str(repository or "")[:200], str(connection_id or "")[:64],
             str(base_branch or "")[:200], json.dumps(plan["preflight"]), actor_id, now, now))
        for item in plan["items"]:
            conn.execute(
                "INSERT INTO crypto_switch_items (id, incident_id, org_id, asset_key, owner, team, priority_score, priority, rank, "
                "batch, server_type, observed, factors_json, repository, change_path, change_content, change_howto, state, note, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'vulnerable', ?, ?)",
                ("ksi_" + secrets.token_hex(8), incident_id, org_id, item["asset_key"], item["owner"], item["team"],
                 float(item["priority_score"]), item["priority"], item["rank"], item["batch"], item["server_type"],
                 item["observed"], json.dumps(item["priority_factors"]), item["repository"], item["change_path"],
                 item["change_content"], item["change_howto"],
                 "" if item["observed_confirmed"] else "Scan did not record the exact key size; confirm before merging.", now))
        incident = _get_incident(conn, org_id, incident_id)
        _append_event(conn, org_id, incident, actor_id, "declared",
                      {"broken": incident["broken"], "fallback": incident["fallback"], "affected": len(plan["items"]),
                       "dry_run": bool(dry_run)})
        conn.commit()
    _journal(actor, "crypto_switch.declared", incident_id,
             {"broken": incident["broken"], "fallback": incident["fallback"], "affected": len(plan["items"]),
              "batches": len(plan["batches"]), "dry_run": bool(dry_run), "warnings": plan["preflight"]["warnings"]})
    _notify("crypto_switch.declared", {"incident_id": incident_id, "broken": incident["broken"],
                                       "fallback": incident["fallback"], "affected": len(plan["items"])})
    return incident_status(org_id, incident_id)


def list_incidents(org_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    _init()
    with feature_conn() as conn:
        rows = conn.execute("SELECT * FROM crypto_switch_incidents WHERE org_id = ? ORDER BY created_at DESC LIMIT ?",
                            (org_id, max(1, min(int(limit or 50), 500)))).fetchall()
        out = []
        for row in rows:
            inc = _incident_row(row)
            inc.pop("events", None)
            inc["counts"] = _counts(conn, org_id, inc["id"])
            out.append(inc)
    return out


def _counts(conn, org_id: str, incident_id: str) -> Dict[str, int]:
    counts = {state: 0 for state in ITEM_STATES}
    for row in conn.execute("SELECT state, COUNT(*) AS n FROM crypto_switch_items WHERE org_id = ? AND incident_id = ? GROUP BY state",
                            (org_id, incident_id)).fetchall():
        counts[str(row["state"])] = int(row["n"] or 0)
    counts["total"] = sum(counts[s] for s in ITEM_STATES)
    return counts


def incident_status(org_id: str, incident_id: str, with_changes: bool = False) -> Dict[str, Any]:
    """The live view: counts by state, progress, and every asset with its state and request."""
    _init()
    with feature_conn() as conn:
        incident = _get_incident(conn, org_id, incident_id)
        items = [_item_row(r, with_changes) for r in conn.execute(
            "SELECT * FROM crypto_switch_items WHERE org_id = ? AND incident_id = ? ORDER BY rank", (org_id, incident_id)).fetchall()]
        counts = _counts(conn, org_id, incident_id)
    total = counts["total"]
    incident["counts"] = counts
    incident["progress"] = {"switched": counts["switched"], "total": total,
                            "percent": round(100.0 * counts["switched"] / total, 1) if total else 100.0}
    incident["batches"] = sorted({int(i["batch"]) for i in items})
    incident["next_batch"] = next((int(i["batch"]) for i in items if i["state"] == "vulnerable"), None)
    incident["items"] = items
    return incident


def _require(incident: Dict[str, Any], *statuses: str) -> None:
    if incident["status"] not in statuses:
        raise SwitchError(409, f"The incident is {incident['status']}; this step needs it to be {' or '.join(statuses)}.")


def approve_incident(org_id: str, incident_id: str, actor: Dict[str, str], note: str = "") -> Dict[str, Any]:
    _init()
    with feature_conn() as conn:
        incident = _get_incident(conn, org_id, incident_id)
        _require(incident, "planned")
        now = _now()
        conn.execute("UPDATE crypto_switch_incidents SET status = 'approved', approved_by = ?, approved_at = ?, updated_at = ? "
                     "WHERE org_id = ? AND id = ?", (str(actor.get("actor_id") or ""), now, now, org_id, incident_id))
        incident["status"] = "approved"
        _append_event(conn, org_id, incident, str(actor.get("actor_id") or ""), "approved", {"note": str(note or "")[:500],
                                                                                              "dry_run": incident["dry_run"]})
        conn.commit()
    _journal(actor, "crypto_switch.approved", incident_id, {"dry_run": incident["dry_run"], "note": str(note or "")[:500]})
    return incident_status(org_id, incident_id)


def go_live(org_id: str, incident_id: str, actor: Dict[str, str]) -> Dict[str, Any]:
    """Leave dry-run. The plan goes back to 'planned' and needs a fresh approval before any request opens."""
    _init()
    with feature_conn() as conn:
        incident = _get_incident(conn, org_id, incident_id)
        _require(incident, "planned", "approved")
        conn.execute("UPDATE crypto_switch_incidents SET dry_run = 0, status = 'planned', approved_by = '', approved_at = '', "
                     "updated_at = ? WHERE org_id = ? AND id = ?", (_now(), org_id, incident_id))
        incident["status"] = "planned"
        _append_event(conn, org_id, incident, str(actor.get("actor_id") or ""), "dry_run_disabled", {})
        conn.commit()
    _journal(actor, "crypto_switch.dry_run_disabled", incident_id, {})
    return incident_status(org_id, incident_id)


def cancel_incident(org_id: str, incident_id: str, actor: Dict[str, str], note: str = "") -> Dict[str, Any]:
    _init()
    with feature_conn() as conn:
        incident = _get_incident(conn, org_id, incident_id)
        _require(incident, "planned", "approved", "executing")
        conn.execute("UPDATE crypto_switch_incidents SET status = 'cancelled', updated_at = ? WHERE org_id = ? AND id = ?",
                     (_now(), org_id, incident_id))
        incident["status"] = "cancelled"
        _append_event(conn, org_id, incident, str(actor.get("actor_id") or ""), "cancelled", {"note": str(note or "")[:500]})
        conn.commit()
    _journal(actor, "crypto_switch.cancelled", incident_id, {"note": str(note or "")[:500]})
    return incident_status(org_id, incident_id)


def _pr_body(incident: Dict[str, Any], item: Dict[str, Any]) -> str:
    return (
        f"**Crypto kill switch** declared in Morrow: `{incident['broken']}` is considered broken; this change moves "
        f"**{item['asset_key']}** ({item['server_type']}) to `{incident['fallback']}`.\n\n"
        f"Owner: {item['owner'] or 'unassigned'} · Priority {item['priority'].upper()} (score {int(item['priority_score'])}) · "
        f"Batch {item['batch']}\n\n**How to apply:** {item['change_howto']}\n\n"
        + (f"Reason: {incident['reason']}\n\n" if incident.get("reason") else "")
        + "Nothing has been applied to a live system. Review, test in staging and merge when ready; Morrow then rescans "
        "the endpoint and marks it switched only when the scan observes the new algorithm. To roll back, revert this change."
    )


def execute_batch(org_id: str, incident_id: str, actor: Dict[str, str], batch: Optional[int] = None,
                  open_request: Optional[Callable[..., Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Open the pull requests for one batch (the next pending one by default). An admin calls this
    for every batch. In dry-run it returns the requests it would open and opens none."""
    from services import code_hosts

    _init()
    open_request = open_request or code_hosts.open_change_request
    with feature_conn() as conn:
        incident = _get_incident(conn, org_id, incident_id)
        _require(incident, "approved", "executing")
        rows = conn.execute("SELECT * FROM crypto_switch_items WHERE org_id = ? AND incident_id = ? AND state = 'vulnerable' "
                            "ORDER BY rank", (org_id, incident_id)).fetchall()
        pending = [_item_row(r, True) for r in rows]
    if not pending:
        raise SwitchError(409, "Every asset in this incident already has a request or a configuration to apply.")
    target = int(batch) if batch else int(pending[0]["batch"])
    items = [i for i in pending if int(i["batch"]) == target]
    if not items:
        raise SwitchError(409, f"Batch {target} has nothing left to open.")
    results: List[Dict[str, Any]] = []
    for item in items:
        repo = item["repository"] or incident["repository"]
        title = f"Crypto kill switch: {incident['broken']} -> {incident['fallback']} on {item['asset_key']}"[:200]
        preview = {"asset_key": item["asset_key"], "repository": repo, "file_path": item["change_path"], "title": title,
                   "content": item["change_content"]}
        if incident["dry_run"]:
            results.append({**preview, "outcome": "dry_run"})
            continue
        if not repo:
            _set_item(org_id, item["id"], state="manual_apply",
                      note="No repository is linked to this asset: apply the attached configuration, then rescan.")
            results.append({**preview, "outcome": "manual_apply"})
            continue
        try:
            opened = open_request(org_id, repo, {item["change_path"]: item["change_content"]}, title, _pr_body(incident, item),
                                  base_branch=incident["base_branch"], connection_id=incident["connection_id"])
        except code_hosts.CodeHostError as exc:
            _set_item(org_id, item["id"], state="failed", note=str(exc.detail)[:500])
            results.append({**preview, "outcome": "failed", "error": str(exc.detail)[:500]})
            continue
        _set_item(org_id, item["id"], state="pr_open", pr_url=str(opened.get("url") or ""), pr_number=str(opened.get("number") or ""),
                  connection_id=str(opened.get("connection_id") or incident["connection_id"] or ""), opened_at=_now(),
                  repository=str(opened.get("repository") or repo), note="")
        results.append({**preview, "outcome": "pr_open", "pr_url": opened.get("url")})
    with feature_conn() as conn:
        incident = _get_incident(conn, org_id, incident_id)
        if not incident["dry_run"] and incident["status"] == "approved":
            conn.execute("UPDATE crypto_switch_incidents SET status = 'executing', updated_at = ? WHERE org_id = ? AND id = ?",
                         (_now(), org_id, incident_id))
        _append_event(conn, org_id, incident, str(actor.get("actor_id") or ""), "batch_dry_run" if incident["dry_run"] else "batch_opened",
                      {"batch": target, "outcomes": {o: sum(1 for r in results if r["outcome"] == o) for o in {r["outcome"] for r in results}}})
        conn.commit()
    _journal(actor, "crypto_switch.batch_dry_run" if incident["dry_run"] else "crypto_switch.batch_opened", incident_id,
             {"batch": target, "requests": [{k: r.get(k) for k in ("asset_key", "outcome", "pr_url", "repository")} for r in results]})
    status = incident_status(org_id, incident_id)
    status["batch_result"] = {"batch": target, "dry_run": incident["dry_run"],
                              "requests": [r if incident["dry_run"] else {k: v for k, v in r.items() if k != "content"} for r in results]}
    return status


def _set_item(org_id: str, item_id: str, **fields: Any) -> None:
    fields["updated_at"] = _now()
    cols = ", ".join(f"{k} = ?" for k in fields)
    with feature_conn() as conn:
        conn.execute(f"UPDATE crypto_switch_items SET {cols} WHERE org_id = ? AND id = ?", (*fields.values(), org_id, item_id))
        conn.commit()


def refresh_incident(org_id: str, incident_id: str, actor: Dict[str, str], *,
                     latest_facts: Callable[[List[str]], Dict[str, Dict[str, Any]]],
                     request_rescan: Optional[Callable[[List[str]], str]] = None,
                     request_state: Optional[Callable[..., Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Track every request: merged ones get a rescan, and an asset is switched only when a scan newer
    than the merge (or than the hand-over, for a configuration the customer applies) observes the
    fallback and no longer observes the broken algorithm."""
    from services import code_hosts

    _init()
    request_state = request_state or code_hosts.change_request_state
    with feature_conn() as conn:
        incident = _get_incident(conn, org_id, incident_id)
        items = [_item_row(r) for r in conn.execute(
            "SELECT * FROM crypto_switch_items WHERE org_id = ? AND incident_id = ? ORDER BY rank", (org_id, incident_id)).fetchall()]
    broken = resolve(incident["broken"])
    fallback = resolve(incident["fallback"])
    changes: List[Dict[str, Any]] = []
    for item in items:
        if item["state"] == "pr_open" and item["pr_number"]:
            try:
                st = request_state(org_id, item["repository"], item["pr_number"], connection_id=item["connection_id"])
            except code_hosts.CodeHostError as exc:
                changes.append({"asset_key": item["asset_key"], "error": str(exc.detail)[:200]})
                continue
            if st.get("state") == "merged":
                item.update(state="merged", merged_at=str(st.get("merged_at") or "") or _now())
                _set_item(org_id, item["id"], state="merged", merged_at=item["merged_at"])
                changes.append({"asset_key": item["asset_key"], "state": "merged"})
            elif st.get("state") == "closed":
                _set_item(org_id, item["id"], state="failed", note="The pull request was closed without merging.")
                changes.append({"asset_key": item["asset_key"], "state": "failed"})
    rescan_keys = [i["asset_key"] for i in items if i["state"] == "merged" and not i["rescan_requested_at"]]
    if rescan_keys and request_rescan:
        try:
            scan_id = str(request_rescan(rescan_keys) or "")
        except Exception as exc:  # a rescan that cannot start leaves the asset merged; refresh retries it
            scan_id = ""
            changes.append({"rescan_error": str(exc)[:200]})
        if scan_id:
            now = _now()
            for item in items:
                if item["asset_key"] in rescan_keys:
                    item["rescan_requested_at"] = now
                    _set_item(org_id, item["id"], rescan_scan_id=scan_id, rescan_requested_at=now)
    watch = [i for i in items if i["state"] in ("merged", "rescan_mismatch", "manual_apply")]
    facts = latest_facts([i["asset_key"] for i in watch]) if watch else {}
    for item in watch:
        fact = facts.get(item["asset_key"])
        since = item["updated_at"] if item["state"] == "manual_apply" else (item["merged_at"] or item["updated_at"])
        if not fact or not _after(fact.get("scanned_at"), since):
            continue
        if is_switched(fallback, broken, fact):
            _set_item(org_id, item["id"], state="switched", verified_scan_id=str(fact.get("scan_id") or ""),
                      verified_at=str(fact.get("scanned_at") or ""), note="")
            changes.append({"asset_key": item["asset_key"], "state": "switched", "scan_id": fact.get("scan_id")})
        elif item["state"] != "manual_apply":
            seen = observed(fact, fallback["kind"])
            _set_item(org_id, item["id"], state="rescan_mismatch",
                      note=f"Scan {fact.get('scan_id')} still observes {seen[1] or seen[0] or 'no algorithm'}, not {fallback['name']}.")
            changes.append({"asset_key": item["asset_key"], "state": "rescan_mismatch"})
    status = incident_status(org_id, incident_id)
    done = status["counts"]["total"] > 0 and status["counts"]["switched"] == status["counts"]["total"]
    with feature_conn() as conn:
        incident = _get_incident(conn, org_id, incident_id)
        if done and incident["status"] in ("approved", "executing"):
            conn.execute("UPDATE crypto_switch_incidents SET status = 'completed', updated_at = ? WHERE org_id = ? AND id = ?",
                         (_now(), org_id, incident_id))
            status["status"] = "completed"
        if changes:
            _append_event(conn, org_id, incident, str(actor.get("actor_id") or ""), "refreshed", {"changes": changes[:50]})
        conn.commit()
    if changes:
        _journal(actor, "crypto_switch.refreshed", incident_id, {"changes": changes[:100]})
    if done and status["status"] == "completed":
        _journal(actor, "crypto_switch.completed", incident_id, {"switched": status["counts"]["switched"]})
        _notify("crypto_switch.completed", {"incident_id": incident_id, "switched": status["counts"]["switched"]})
    status["refresh_changes"] = changes
    return status
