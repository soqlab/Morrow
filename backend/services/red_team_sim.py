"""
Red Team Simulation Mode

Simulates a harvest-now-decrypt-later (HNDL) adversary attack against
the organization's known asset inventory.

The simulation models:
  1. Adversary target selection — which assets would be harvested first
     (priority = weakest crypto × highest data sensitivity × exposure)
  2. Decryption timeline — estimated year when each asset's traffic becomes
     readable, per the Q-Day probability model
  3. Blast radius of a Q-Day event — which assets are simultaneously exposed
  4. Kill-chain steps — how an adversary would move through the network
  5. Recommended countermeasures with priority ordering

All computation is deterministic and based on scanned data — no external
calls required. Uses the same Q-Day model as the Timeline Visualizer.
"""

from __future__ import annotations

import logging
import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from db_feature_store import feature_conn

logger = logging.getLogger(__name__)


# ── Q-Day model ────────────────────────────────────────────────────────────────
# Midpoints are expressed relative to RSA-2048. The RSA-2048 anchor is read from
# the Q-Intel model (services/q_intel.py), the platform's single source of Q-Day
# years; _QDAY_PARAMS keeps only the per-algorithm offsets and steepness.

_RSA2048_REFERENCE_MIDPOINT = 2031.5  # the offsets below were authored against this value

_QDAY_PARAMS: Dict[str, Dict[str, float]] = {
    "RSA-2048":   {"midpoint": 2031.5, "steepness": 1.2},
    "RSA-1024":   {"midpoint": 2029.0, "steepness": 1.4},
    "RSA-4096":   {"midpoint": 2034.0, "steepness": 1.0},
    "ECDSA-256":  {"midpoint": 2030.5, "steepness": 1.3},
    "ECDSA-384":  {"midpoint": 2031.0, "steepness": 1.2},
    "ECDH-256":   {"midpoint": 2030.5, "steepness": 1.3},
    "DH-2048":    {"midpoint": 2031.0, "steepness": 1.2},
    "DH-1024":    {"midpoint": 2028.5, "steepness": 1.5},
    "3DES":       {"midpoint": 2027.5, "steepness": 1.6},
    "RC4":        {"midpoint": 2026.5, "steepness": 2.0},
    "DEFAULT":    {"midpoint": 2031.0, "steepness": 1.2},
}

_RISK_PRIORITY = {"critical": 4, "high": 3, "medium": 2, "low": 1, "safe": 0}

# Data sensitivity by port heuristic
_PORT_SENSITIVITY: Dict[int, Tuple[str, int]] = {
    443:   ("HTTPS / Web",       3),
    8443:  ("HTTPS / Admin",     4),
    636:   ("LDAPS / Auth",      5),
    993:   ("IMAPS / Email",     4),
    995:   ("POP3S / Email",     4),
    3306:  ("MySQL / Database",  5),
    5432:  ("PostgreSQL / DB",   5),
    6379:  ("Redis / Cache",     4),
    27017: ("MongoDB / DB",      5),
    22:    ("SSH / Admin",       4),
    465:   ("SMTPS / Email",     3),
    1194:  ("OpenVPN",           4),
}

_DEFAULT_SENSITIVITY = ("Unknown Service", 2)


_ANCHOR_CACHE: Dict[str, float] = {}
_ANCHOR_TTL_SECONDS = 300.0


def _rsa2048_anchor() -> float:
    """RSA-2048 50% year from the Q-Intel model (cached briefly; the model reads the DB)."""
    import time
    now = time.monotonic()
    if "year" in _ANCHOR_CACHE and now - _ANCHOR_CACHE.get("at", 0.0) < _ANCHOR_TTL_SECONDS:
        return _ANCHOR_CACHE["year"]
    try:
        from services.q_intel import q_day_crossing_year
        year = q_day_crossing_year("rsa2048", 0.5)
        anchor = float(year) if year is not None else 2100.0
    except Exception:
        logger.exception("red team simulation could not read the Q-Intel model; using the authored midpoint")
        anchor = _RSA2048_REFERENCE_MIDPOINT
    _ANCHOR_CACHE.update({"year": anchor, "at": now})
    return anchor


def _reference_years() -> Dict[str, float]:
    """Scenario years (accelerated 10% / expected 50% / conservative 90%) from the Q-Intel model."""
    try:
        from services.q_intel import q_day_reference
        ref = q_day_reference("rsa2048")
        return {
            "accelerated": float(ref.get("accelerated_year") or 2100),
            "expected": float(ref.get("expected_year") or 2100),
            "conservative": float(ref.get("conservative_year") or 2100),
        }
    except Exception:
        logger.exception("red team simulation could not read Q-Intel reference years")
        anchor = _rsa2048_anchor()
        return {"accelerated": anchor - 3.0, "expected": anchor, "conservative": anchor + 3.0}


def red_team_model_basis() -> Dict[str, Any]:
    from services.model_basis import model_basis
    try:
        from services.q_intel import MODEL_AS_OF
    except Exception:
        MODEL_AS_OF = ""
    offsets = ", ".join(
        f"{alg} {p['midpoint'] - _RSA2048_REFERENCE_MIDPOINT:+.1f}y"
        for alg, p in _QDAY_PARAMS.items() if alg not in ("RSA-2048", "DEFAULT")
    )
    return model_basis(
        kind="model",
        summary=(
            "A simulated adversary scenario over your scanned assets. Decryption years come from the Q-Intel "
            "model; they are not predictions of real attacks and no adversary activity was observed."
        ),
        assumptions=[
            f"RSA-2048 reaches 50% break probability in {_rsa2048_anchor():.1f} (Q-Intel model; see /q-intel/model).",
            f"Other algorithms are offset from RSA-2048: {offsets}.",
            "Scenario years: pessimistic = Q-Intel 10% year, realistic = 50% year, optimistic = 90% year.",
            "Target priority = risk weight x port-based data sensitivity (1-5) x urgency.",
            "Kill-chain phases are generic templates, not observed activity.",
        ],
        sources=["services/q_intel.py model (model_basis on /q-intel/model)"],
        as_of=MODEL_AS_OF,
    )


def _q_day_prob(algorithm: str, year: float) -> float:
    """Logistic probability that a CRQC can break `algorithm` by `year`."""
    params = _QDAY_PARAMS.get(algorithm, _QDAY_PARAMS["DEFAULT"])
    k = params["steepness"]
    m = params["midpoint"] - _RSA2048_REFERENCE_MIDPOINT + _rsa2048_anchor()
    x = -k * (year - m)
    if x > 700:
        return 0.0
    return 1.0 / (1.0 + math.exp(x))


def _decryption_year(algorithm: str, threshold: float = 0.50) -> float:
    """
    Estimate the year when adversary decryption probability crosses `threshold`.
    Binary search on the logistic curve.
    """
    lo, hi = 2000.0, 2100.0
    for _ in range(50):
        mid = (lo + hi) / 2.0
        if _q_day_prob(algorithm, mid) < threshold:
            lo = mid
        else:
            hi = mid
    return round((lo + hi) / 2.0, 1)


def _normalize_algorithm(alg: str, key_bits: int) -> str:
    """Normalize scanner algorithm labels to the model's known keys."""
    alg = (alg or "").upper()
    if "RSA" in alg:
        if key_bits and key_bits <= 1024:  return "RSA-1024"
        if key_bits and key_bits >= 4096:  return "RSA-4096"
        return "RSA-2048"
    if "ECDSA" in alg or "EC" in alg:
        if key_bits and key_bits >= 384:   return "ECDSA-384"
        return "ECDSA-256"
    if "ECDH" in alg:  return "ECDH-256"
    if "DH" in alg:
        if key_bits and key_bits <= 1024:  return "DH-1024"
        return "DH-2048"
    if "3DES" in alg or "TRIPLE" in alg: return "3DES"
    if "RC4" in alg:   return "RC4"
    return "DEFAULT"


# ── DB ─────────────────────────────────────────────────────────────────────────

def _load_assets(org_id: str) -> List[Dict[str, Any]]:
    """Most recent scan result per asset, newest first.

    This previously selected host, port, algorithm, key_bits, risk_level and
    scanned_at from `scans` where org_id -- and not one of those seven columns
    exists. `scans` holds id, organization_id, status, created_at and the JSON
    blobs; the per-asset facts live in `scan_results`. Every call raised
    OperationalError, a bare `except` returned [], and the caller reported "No
    scanned assets found. Run a scan first." So the simulation ran on zero
    assets on every deployment, and told the operator it was their fault.

    Failures are now logged rather than swallowed, because that silence is what
    let this survive.
    """
    try:
        with feature_conn() as conn:
            rows = conn.execute(
                """
                SELECT asset_key, risk_level, key_type, sig_algorithm, scanned_at
                FROM scan_results
                WHERE organization_id = ?
                ORDER BY scanned_at DESC
                """,
                (org_id,),
            ).fetchall()
    except Exception:
        logger.exception("red team simulation could not read scan_results")
        return []

    out: List[Dict[str, Any]] = []
    for row in rows:
        key = str(row["asset_key"] or "").strip()
        if not key:
            continue
        # asset_key is "host:port"; rpartition keeps IPv6 literals intact because
        # only the final colon is treated as the separator.
        host, sep, port = key.rpartition(":")
        if not sep:
            host, port = key, "443"
        try:
            port_n = int(port)
        except ValueError:
            host, port_n = key, 443
        out.append({
            "host": host,
            "port": port_n,
            # _normalize_algorithm reads the key type ("RSA", "EC"); key size is
            # not persisted on scan_results, and it degrades to the family
            # default rather than guessing.
            "algorithm": str(row["key_type"] or row["sig_algorithm"] or ""),
            "key_bits": 0,
            "risk_level": str(row["risk_level"] or "low"),
            "scanned_at": str(row["scanned_at"] or ""),
        })
    return out


# ── Target scoring ─────────────────────────────────────────────────────────────

def _score_asset(asset: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compute adversary target priority score for one asset.
    Score = risk_weight × sensitivity × q_day_urgency
    """
    algorithm  = _normalize_algorithm(asset.get("algorithm", ""), asset.get("key_bits") or 0)
    risk_level = (asset.get("risk_level") or "low").lower()
    port       = int(asset.get("port") or 443)

    risk_w     = _RISK_PRIORITY.get(risk_level, 1)
    svc_label, sensitivity = _PORT_SENSITIVITY.get(port, _DEFAULT_SENSITIVITY)

    now_year   = datetime.now(timezone.utc).year + datetime.now(timezone.utc).month / 12.0
    qday_now   = _q_day_prob(algorithm, now_year)
    qday_3y    = _q_day_prob(algorithm, now_year + 3)
    decrypt_yr = _decryption_year(algorithm)
    years_left = max(0.0, decrypt_yr - now_year)

    # Urgency: higher when fewer years remain
    urgency    = max(0.0, 1.0 - years_left / 15.0)

    score      = round(risk_w * sensitivity * (1.0 + urgency), 2)

    return {
        "host":          asset.get("host", ""),
        "port":          port,
        "service":       svc_label,
        "algorithm":     algorithm,
        "key_bits":      asset.get("key_bits"),
        "risk_level":    risk_level,
        "sensitivity":   sensitivity,
        "qday_prob_now": round(qday_now * 100, 1),
        "qday_prob_3y":  round(qday_3y * 100, 1),
        "decrypt_year":  decrypt_yr,
        "years_until_decrypt": round(years_left, 1),
        "target_score":  score,
        "scanned_at":    asset.get("scanned_at", ""),
    }


# ── Kill chain ─────────────────────────────────────────────────────────────────

_KILL_CHAIN_TEMPLATES: List[Dict[str, Any]] = [
    {
        "phase":       "1 — Reconnaissance",
        "tactic":      "Passive TLS fingerprinting",
        "description": "Adversary passively records TLS handshakes from internet-facing endpoints using mass scanning (Censys, Shodan) to identify weak key exchange and cipher suites.",
        "ioc":         "Unusual inbound SYN bursts and TLS handshake-only connections from scanning infrastructure",
        "mitigation":  "Deploy TLS fingerprinting detection (JA3/JA4) at the perimeter firewall",
    },
    {
        "phase":       "2 — Harvest",
        "tactic":      "Encrypted traffic capture",
        "description": "Adversary begins long-term capture of all encrypted traffic to targeted hosts, storing ciphertext in bulk storage for later decryption when a CRQC becomes available.",
        "ioc":         "Sustained high-volume port-mirror or BGP hijack activity; ISP-level traffic anomalies",
        "mitigation":  "Implement Perfect Forward Secrecy (PFS) with ephemeral Diffie-Hellman; enable Certificate Transparency monitoring",
    },
    {
        "phase":       "3 — Wait (Q-Day approach)",
        "tactic":      "CRQC capability acquisition",
        "description": "Adversary acquires access to a Cryptographically Relevant Quantum Computer — either through nation-state program or as-a-service from a hostile actor. Estimated probability per algorithm shown below.",
        "ioc":         "Public announcements of CRQC milestones; unusual demand for quantum computing cloud credits",
        "mitigation":  "Begin PQC migration immediately — harvested traffic cannot be un-captured",
    },
    {
        "phase":       "4 — Decrypt",
        "tactic":      "Retroactive decryption via Shor's algorithm",
        "description": "Using harvested ciphertext and the CRQC, adversary runs Shor's algorithm to factor RSA moduli or solve discrete logarithm for ECDH, recovering plaintext session data, credentials, and keys.",
        "ioc":         "N/A — decryption happens offline; no network indicator",
        "mitigation":  "Protect all currently-in-transit sensitive data with PQC-safe algorithms NOW",
    },
    {
        "phase":       "5 — Exploit",
        "tactic":      "Credential replay and lateral movement",
        "description": "With decrypted session data (passwords, API keys, certificates, session tokens), adversary re-authenticates to internal systems, pivots laterally, and exfiltrates data or implants backdoors.",
        "ioc":         "Impossible travel logins; auth tokens replayed after long dormancy; unusual privileged access",
        "mitigation":  "Zero-trust architecture, short-lived credentials, continuous auth re-verification",
    },
]


# ── Blast radius ───────────────────────────────────────────────────────────────

def _compute_blast_radius(
    targets: List[Dict[str, Any]],
    qday_year: float,
) -> Dict[str, Any]:
    """
    At a given Q-Day year, which assets are simultaneously exposed?
    """
    exposed    = [t for t in targets if t["decrypt_year"] <= qday_year]
    safe       = [t for t in targets if t["decrypt_year"] > qday_year]

    exposed_score = sum(t["target_score"] for t in exposed)
    total_score   = sum(t["target_score"] for t in targets) or 1

    risk_pct = round(exposed_score / total_score * 100, 1)

    by_service: Dict[str, int] = {}
    for t in exposed:
        by_service[t["service"]] = by_service.get(t["service"], 0) + 1

    return {
        "qday_year":        qday_year,
        "exposed_count":    len(exposed),
        "safe_count":       len(safe),
        "total_count":      len(targets),
        "risk_exposure_pct":risk_pct,
        "exposed_services": by_service,
        "most_exposed":     exposed[:5],
    }


# ── Public API ─────────────────────────────────────────────────────────────────

def run_simulation(
    org_id: str,
    qday_scenario_year: Optional[float] = None,
    top_n_targets: int = 20,
    threshold_pct: float = 50.0,
) -> Dict[str, Any]:
    """
    Run the full red team simulation against an org's asset inventory.

    Returns:
      - target_list: assets sorted by adversary priority (highest first)
      - kill_chain: templated attack phases with org-specific commentary
      - blast_radius: assets exposed at Q-Day scenarios (optimistic/realistic/pessimistic)
      - decryption_timeline: per-asset estimated decrypt year
      - countermeasures: prioritized remediation recommendations
    """
    assets = _load_assets(org_id)
    if not assets:
        return {
            "ok":    False,
            "error": "No scanned assets found. Run a scan first to populate the asset inventory.",
            "org_id": org_id,
        }

    # Deduplicate by host:port
    seen: set = set()
    unique_assets = []
    for a in assets:
        key = f"{a.get('host')}:{a.get('port')}"
        if key not in seen:
            seen.add(key)
            unique_assets.append(a)

    # Score all targets
    scored = [_score_asset(a) for a in unique_assets]
    scored.sort(key=lambda x: x["target_score"], reverse=True)

    datetime.now(timezone.utc).year + datetime.now(timezone.utc).month / 12.0

    # Q-Day scenarios, from the Q-Intel model's reference years
    ref_years    = _reference_years()
    optimistic   = qday_scenario_year or ref_years["conservative"]
    realistic    = qday_scenario_year or ref_years["expected"]
    pessimistic  = qday_scenario_year or ref_years["accelerated"]

    blast_opt   = _compute_blast_radius(scored, optimistic)
    blast_real  = _compute_blast_radius(scored, realistic)
    blast_pess  = _compute_blast_radius(scored, pessimistic)

    # Summary stats
    total         = len(scored)
    critical_n    = sum(1 for t in scored if t["risk_level"] in ("critical", "high"))
    already_vuln  = sum(1 for t in scored if t["qday_prob_now"] >= threshold_pct)
    vuln_3y       = sum(1 for t in scored if t["qday_prob_3y"] >= threshold_pct)
    avg_yrs       = round(sum(t["years_until_decrypt"] for t in scored) / total, 1) if total else 0

    # Earliest and latest decrypt
    earliest = min(scored, key=lambda x: x["decrypt_year"]) if scored else None
    latest   = max(scored, key=lambda x: x["decrypt_year"]) if scored else None

    # Kill chain with org-specific data
    kill_chain = []
    for step in _KILL_CHAIN_TEMPLATES:
        kc = dict(step)
        if step["phase"].startswith("3"):
            alg_lines = []
            for t in scored[:5]:
                alg_lines.append(
                    f"  • {t['host']}:{t['port']} ({t['algorithm']}) — "
                    f"{t['qday_prob_now']}% now, {t['qday_prob_3y']}% in 3 years"
                )
            kc["org_specific"] = "\n".join(alg_lines) if alg_lines else "No vulnerable assets found."
        kill_chain.append(kc)

    # Countermeasures
    countermeasures = _build_countermeasures(scored, blast_real)

    # Decryption timeline: first 30 assets sorted by decrypt year
    timeline = sorted(scored[:30], key=lambda x: x["decrypt_year"])

    return {
        "ok":           True,
        "org_id":       org_id,
        "simulated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_assets":         total,
            "critical_high":        critical_n,
            "already_vulnerable_pct":  round(already_vuln / total * 100, 1) if total else 0,
            "vulnerable_in_3y_pct": round(vuln_3y / total * 100, 1) if total else 0,
            "avg_years_to_decrypt": avg_yrs,
            "earliest_decrypt":     earliest["host"] + ":" + str(earliest["port"]) + f" ({earliest['decrypt_year']})" if earliest else "",
            "latest_decrypt":       latest["host"]   + ":" + str(latest["port"])   + f" ({latest['decrypt_year']})" if latest else "",
        },
        "target_list":   scored[:top_n_targets],
        "kill_chain":    kill_chain,
        # Key names are kept for console compatibility; the years inside each
        # entry (qday_year) and scenario_years come from the Q-Intel model.
        "blast_radius": {
            "pessimistic_2028": blast_pess,
            "realistic_2031":   blast_real,
            "optimistic_2035":  blast_opt,
        },
        "scenario_years": {
            "pessimistic": pessimistic,
            "realistic":   realistic,
            "optimistic":  optimistic,
        },
        "decryption_timeline": timeline,
        "countermeasures":     countermeasures,
        "model_basis":         red_team_model_basis(),
    }


def _build_countermeasures(
    targets: List[Dict[str, Any]],
    blast: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Generate prioritized countermeasure recommendations from the asset list."""
    recs = []
    urgent = [t for t in targets if t["years_until_decrypt"] < 7 and t["risk_level"] in ("critical", "high")]
    medium  = [t for t in targets if 7 <= t["years_until_decrypt"] < 10]

    if urgent:
        host_list = ", ".join(f"{t['host']}:{t['port']}" for t in urgent[:3])
        recs.append({
            "priority":    1,
            "label":       "IMMEDIATE — Migrate high-risk short-fuse assets",
            "description": f"{len(urgent)} asset(s) are both high-risk and within 7-year decryption horizon: {host_list}",
            "action":      "Deploy ML-KEM-768 hybrid key exchange on these assets within 90 days. Use the nginx or openssl playbook.",
            "playbook":    "nginx",
        })

    if blast.get("exposed_count", 0) > blast.get("total_count", 1) * 0.5:
        recs.append({
            "priority":    2,
            "label":       f"HIGH — >50% of assets exposed at the model's realistic Q-Day ({blast.get('qday_year', 0):.0f})",
            "description": f"{blast['exposed_count']} of {blast['total_count']} assets would be decrypted simultaneously in the realistic scenario ({blast.get('qday_year', 0):.0f}).",
            "action":      "Initiate org-wide PQC migration program. Prioritize assets by sensitivity score.",
            "playbook":    None,
        })

    recs.append({
        "priority":    3,
        "label":       "MEDIUM — Enable Perfect Forward Secrecy everywhere",
        "description": "PFS with ephemeral ECDHE ensures captured ciphertext cannot be decrypted even if the long-term key is later compromised.",
        "action":      "Audit all TLS endpoints: require ECDHE or DHE cipher suites. Disable static RSA key exchange.",
        "playbook":    "nginx",
    })

    if medium:
        recs.append({
            "priority":    4,
            "label":       f"MEDIUM — {len(medium)} assets in 7–10 year window",
            "description": "These assets will become vulnerable within a decade. Plan migration in next annual cycle.",
            "action":      "Add to PQC migration roadmap. Target ML-KEM-768 + ML-DSA-65 by 2027.",
            "playbook":    None,
        })

    recs.append({
        "priority":    5,
        "label":       "LOW — Certificate rotation cadence",
        "description": "Shorter certificate lifetimes reduce the window for post-quantum attacks on long-lived certificates.",
        "action":      "Set max certificate validity to 90 days (ACME/Let's Encrypt) or 1 year for internal CA.",
        "playbook":    "openssl",
    })

    recs.append({
        "priority":    6,
        "label":       "LOW — Enable HNDL canary monitoring",
        "description": "Deploy canary endpoints that alert when encrypted traffic to them is captured and later replayed.",
        "action":      "Configure PQC Scanner canary module with token-based endpoints on critical services.",
        "playbook":    None,
    })

    return recs


def simulate_qday_event(
    org_id: str,
    qday_year: float,
) -> Dict[str, Any]:
    """
    Simulate what happens at a specific Q-Day year — which assets decrypt and what's the impact.
    Lighter call than run_simulation; used for the interactive slider in the UI.
    """
    assets = _load_assets(org_id)
    if not assets:
        return {"ok": False, "error": "No assets found"}

    seen: set = set()
    unique = []
    for a in assets:
        k = f"{a.get('host')}:{a.get('port')}"
        if k not in seen:
            seen.add(k)
            unique.append(a)

    scored = [_score_asset(a) for a in unique]
    blast  = _compute_blast_radius(scored, qday_year)

    return {
        "ok":       True,
        "org_id":   org_id,
        "qday_year":qday_year,
        **blast,
        "model_basis": red_team_model_basis(),
    }
