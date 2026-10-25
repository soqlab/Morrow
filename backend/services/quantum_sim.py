"""
Quantum Simulation Room — Detonate Q-Day

A timed cascade simulation: press "Detonate" and watch a quantum computer
break your infrastructure in real time. Returns a sequence of timestamped
events — key broken, cert compromised, service exposed, data store accessed —
that the frontend animates as a live attack replay.

Scenario timing assumptions (for animation only — not estimates of real
quantum runtimes; published resource estimates such as Gidney 2025 put
RSA-2048 at days, not hours, on hardware that does not yet exist):
  RSA-2048 key:    1 hour (scenario)
  RSA-4096 key:    4 hours (scenario)
  ECC-256  key:    30 minutes (scenario)
  ECC-384  key:    2 hours (scenario)
  Unknown classical: 1.5 hours (scenario)

Cascade timing (after key is broken):
  Cert compromise:      T + 2 min (cert chain verification cracked)
  Service credential:   T + 10 min (private key used to decrypt session)
  Data store exposure:  T + 45 min (decrypted sessions replayed)
  Full audit:           T + 4 hours (all historical sessions decoded)

All times are in simulation-seconds. The frontend scales them with a
speed multiplier (1× = wall-clock, 100× = compressed demo mode).
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Set


_DEFAULT_EXPOSURE_USD = {"data_store": 200_000, "infra": 500_000, "service": 100_000}


def simulation_model_basis() -> Dict[str, Any]:
    from services.model_basis import model_basis
    return model_basis(
        kind="model",
        summary=(
            "A scripted scenario that animates how a key compromise would cascade through your dependency graph; "
            "the break times and dollar figures are scenario assumptions, not estimates of real attacks."
        ),
        assumptions=[
            "Key break times (scenario): " + ", ".join(
                f"{k} {v // 60} min" for k, v in _KEY_BREAK_SECONDS.items() if v is not None
            ) + "; post-quantum keys are not broken.",
            "Cascade delays after a break (scenario): certificates +2 min, services +10 min, infrastructure +30 min, data stores +45 min.",
            "Nodes without an exposure figure are counted at: " + ", ".join(
                f"{k} ${v:,}" for k, v in _DEFAULT_EXPOSURE_USD.items()
            ) + ".",
        ],
        sources=[
            "Gidney 2025 — How to factor 2048 bit RSA integers with less than a million noisy qubits (runtime under a week): https://arxiv.org/abs/2505.15917",
        ],
        as_of="2026-09",
    )


# ── Key break time in simulation seconds (scenario assumption, not a runtime estimate) ─
_KEY_BREAK_SECONDS: Dict[str, int] = {
    "rsa1024":   600,       # 10 min sim = 15 min real
    "rsa2048":   3_600,     # 1 hr
    "rsa3072":   7_200,     # 2 hr
    "rsa4096":   14_400,    # 4 hr
    "ec256":     1_800,     # 30 min
    "ecdsa256":  1_800,
    "ecdh256":   1_800,
    "ec384":     7_200,     # 2 hr
    "ecdsa384":  7_200,
    "x25519":    2_700,     # 45 min
    "dh_classical": 10_800, # 3 hr
    "unknown":   5_400,     # 1.5 hr
    "pq":       None,      # not breakable
}

# Color palette for the simulation
_EVENT_COLORS = {
    "quantum_target":   "#a78bfa",
    "key_break":        "#f87171",
    "cert_compromise":  "#fb923c",
    "service_expose":   "#fbbf24",
    "data_access":      "#ef4444",
    "credential_steal": "#f97316",
    "cascade_complete": "#dc2626",
    "safe":             "#63e6be",
}


def _classify_key(key_type: str, key_bits: int) -> str:
    kt = (key_type or "").lower().replace("-", "").replace("_", "")
    bits = int(key_bits or 0)
    if any(x in kt for x in ("mlkem", "kyber", "dilithium", "slh", "falcon", "pq")):
        return "pq"
    if "rsa" in kt:
        if bits <= 1024: return "rsa1024"
        if bits <= 2048: return "rsa2048"
        if bits <= 3072: return "rsa3072"
        return "rsa4096"
    if "ec" in kt or "ecdsa" in kt or "ecdh" in kt or "x25519" in kt:
        if bits <= 256 or "256" in kt or "25519" in kt: return "ec256"
        return "ec384"
    if "dh" in kt:
        return "dh_classical"
    return "unknown"


def _node_id(label: str) -> str:
    return hashlib.md5(label.encode(), usedforsecurity=False).hexdigest()[:14]


def build_simulation_graph(blast_radius_graph: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich a blast-radius graph with timing data for animation.
    Returns the graph augmented with break_time_seconds per node.
    """
    nodes = blast_radius_graph.get("nodes", [])
    enriched = []
    for node in nodes:
        kt = str(node.get("key_type") or "unknown")
        kb = int(node.get("key_bits") or 0)
        key_class = _classify_key(kt, kb)
        break_seconds = _KEY_BREAK_SECONDS.get(key_class)
        enriched.append({
            **node,
            "key_class": key_class,
            "break_seconds": break_seconds,
            "is_quantum_safe": break_seconds is None,
        })
    return {**blast_radius_graph, "nodes": enriched, "model_basis": simulation_model_basis()}


def run_detonation(
    target_node_id: str,
    graph: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Simulate a quantum computer attacking `target_node_id` and cascading
    through the dependency graph.

    Returns:
      - events: time-ordered list of attack events
      - total_duration_seconds: when the last node falls
      - max_exposure_usd: cumulative financial exposure
      - attacker_log: narrative text log (what the attacker sees)
    """
    by_id: Dict[str, Dict[str, Any]] = {n["id"]: n for n in graph.get("nodes", [])}
    fwd: Dict[str, List[str]] = {}
    for e in graph.get("edges", []):
        fwd.setdefault(e["from"], []).append(e["to"])

    target = by_id.get(target_node_id)
    if not target:
        return {"error": f"Node {target_node_id} not found in graph", "events": []}

    kt = str(target.get("key_type") or "unknown")
    kb = int(target.get("key_bits") or 0)
    key_class = _classify_key(kt, kb)
    break_secs = _KEY_BREAK_SECONDS.get(key_class)

    if break_secs is None:
        return {
            "events": [{
                "t": 0, "type": "safe", "node_id": target_node_id,
                "node_label": target.get("label", target_node_id),
                "message": f"{target.get('label')} uses {kt} — quantum-safe. No cascade.",
                "color": _EVENT_COLORS["safe"],
            }],
            "total_duration_seconds": 0,
            "is_quantum_safe": True,
            "max_exposure_usd": 0,
            "attacker_log": ["Target uses post-quantum cryptography. Unable to break."],
            "model_basis": simulation_model_basis(),
        }

    events: List[Dict[str, Any]] = []
    attacker_log: List[str] = []
    node_break_times: Dict[str, int] = {}
    total_exposure = 0.0

    # Phase 1: Quantum computer acquires target
    events.append({
        "t": 0, "type": "quantum_target", "node_id": target_node_id,
        "node_label": target.get("label", ""),
        "message": f"Quantum computer targeting {target.get('label', '')} ({kt} {kb}-bit key)…",
        "color": _EVENT_COLORS["quantum_target"],
    })
    attacker_log.append(f"[T+0s] Targeting {target.get('label', '')} — {kt} {kb}-bit")

    # Phase 2: Key broken
    t_break = break_secs
    node_break_times[target_node_id] = t_break
    events.append({
        "t": t_break, "type": "key_break", "node_id": target_node_id,
        "node_label": target.get("label", ""),
        "message": f"Private key for {target.get('label', '')} BROKEN. All sessions encrypted with this key are now readable.",
        "color": _EVENT_COLORS["key_break"],
        "severity": "critical",
    })
    attacker_log.append(f"[T+{_fmt_t(t_break)}] KEY BROKEN: {target.get('label', '')} {kt}")

    # Phase 3: BFS cascade with timing
    visited: Set[str] = {target_node_id}
    queue = [target_node_id]

    while queue:
        cur_id = queue.pop(0)
        cur_break = node_break_times.get(cur_id, t_break)
        by_id.get(cur_id, {})

        for next_id in fwd.get(cur_id, []):
            if next_id in visited:
                continue
            visited.add(next_id)
            queue.append(next_id)
            next_node = by_id.get(next_id, {})
            ntype = next_node.get("type", "service")
            label = next_node.get("label", next_id)

            # Timing depends on node type
            if ntype in ("leaf_cert", "intermediate_ca"):
                delay = 120    # 2 min after key break (scenario)
                etype = "cert_compromise"
            elif ntype == "data_store":
                delay = 2_700  # 45 min after previous compromise (scenario)
                etype = "data_access"
                total_exposure += float(next_node.get("exposure_usd") or _DEFAULT_EXPOSURE_USD["data_store"])
            elif ntype == "infra":
                delay = 1_800  # 30 min (scenario)
                etype = "service_expose"
                total_exposure += float(next_node.get("exposure_usd") or _DEFAULT_EXPOSURE_USD["infra"])
            else:
                delay = 600    # 10 min (scenario)
                etype = "service_expose"
                total_exposure += float(next_node.get("exposure_usd") or _DEFAULT_EXPOSURE_USD["service"])

            t_event = cur_break + delay
            node_break_times[next_id] = t_event

            msg_map = {
                "cert_compromise": f"Certificate {label} compromised — can now forge identity",
                "service_expose": f"Service {label} sessions decrypted — credentials extracted",
                "data_access": f"Data store {label} ACCESSED — all historical records readable",
                "credential_steal": f"Credentials for {label} stolen",
            }

            events.append({
                "t": t_event,
                "type": etype,
                "node_id": next_id,
                "node_label": label,
                "message": msg_map.get(etype, f"{label} compromised"),
                "color": _EVENT_COLORS.get(etype, "#f87171"),
                "node_type": ntype,
                "exposure_usd": next_node.get("exposure_usd", 0),
            })
            attacker_log.append(f"[T+{_fmt_t(t_event)}] {etype.upper()}: {label}")

    # Phase 4: Cascade complete
    total_dur = max((e["t"] for e in events), default=t_break)
    events.append({
        "t": total_dur + 60,
        "type": "cascade_complete",
        "node_id": "",
        "node_label": "CASCADE COMPLETE",
        "message": f"Full cascade complete. {len(visited)} nodes compromised. ${total_exposure/1e6:.1f}M in data exposure.",
        "color": _EVENT_COLORS["cascade_complete"],
        "severity": "critical",
    })
    attacker_log.append(
        f"[T+{_fmt_t(total_dur)}] CASCADE COMPLETE — {len(visited)} nodes, "
        f"${total_exposure/1e6:.1f}M exposure"
    )

    events.sort(key=lambda e: e["t"])

    def _fmt_usd(v: float) -> str:
        if v >= 1e9: return f"${v/1e9:.1f}B"
        if v >= 1e6: return f"${v/1e6:.1f}M"
        if v >= 1e3: return f"${v/1e3:.0f}K"
        return f"${v:.0f}"

    return {
        "target_node": target,
        "key_class": key_class,
        "events": events,
        "total_duration_seconds": total_dur,
        "nodes_compromised": len(visited),
        "services_exposed": sum(1 for n in visited if by_id.get(n, {}).get("type") == "service"),
        "data_stores_accessed": sum(1 for n in visited if by_id.get(n, {}).get("type") == "data_store"),
        "max_exposure_usd": round(total_exposure, 2),
        "max_exposure_fmt": _fmt_usd(total_exposure),
        "attacker_log": attacker_log,
        "is_quantum_safe": False,
        "model_basis": simulation_model_basis(),
    }


def _fmt_t(secs: int) -> str:
    if secs < 60: return f"{secs}s"
    if secs < 3600: return f"{secs//60}m{secs%60:02d}s"
    return f"{secs//3600}h{(secs%3600)//60:02d}m"
