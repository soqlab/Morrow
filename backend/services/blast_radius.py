"""
Cryptographic Blast Radius Graph — enterprise-grade

Models the cascade impact when a single key, certificate, or CA is broken
by a quantum computer. When a root CA key is broken, every cert it signed
is compromised — and every service using those certs, and every downstream
service those services call.

Enterprise additions over the basic version:
  - HNDL financial exposure per cascade ($ total exposure if this CA breaks)
  - Manual dependency edges (user-defined service→service relationships)
  - Persistent custom edges in SQLite
  - Export graph as JSON report
  - Severity + financial exposure integrated into simulation result

Node types:
  root_ca         — self-signed root certificate authority
  intermediate_ca — intermediate CA (signed by a root/intermediate)
  leaf_cert       — leaf certificate bound to a specific service
  service         — scanned TLS/HTTPS endpoint
  data_store      — database or storage service (inferred from port)
  infra           — infrastructure service (Kubernetes, Docker, etcd)

Edges:
  ca_signs     — CA signed this cert or sub-CA
  cert_binds   — cert is used by this service
  depends_on   — user-defined service dependency (custom)
"""

from __future__ import annotations

import hashlib
import re
import secrets
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple


_DATA_STORE_PORTS: Set[int] = {5432, 3306, 1433, 27017, 6379, 9200, 2379, 7000, 7001, 1521}
_INFRA_PORTS: Set[int] = {6443, 2376, 2380, 10250, 8883, 8001, 9000}

# HNDL financial exposure per port category — mirrors hndl.py profiles
_PORT_EXPOSURE_USD: Dict[int, float] = {
    443:   200_000,
    8443:  150_000,
    80:    100_000,
    8080:   80_000,
    5432: 2_000_000,
    3306: 1_500_000,
    1433: 2_500_000,
    27017:  800_000,
    6379:   400_000,
    9200: 1_200_000,
    2379: 1_800_000,
    7000:   600_000,
    7001:   600_000,
    1521: 3_000_000,
    636:  3_000_000,
    389:  2_500_000,
    25:     200_000,
    587:    200_000,
    993:    150_000,
    22:     500_000,
    2222:   500_000,
    6443: 2_000_000,
    10250: 1_500_000,
}
_DEFAULT_EXPOSURE_USD = 100_000


def _node_id(label: str) -> str:
    return hashlib.md5(label.encode(), usedforsecurity=False).hexdigest()[:14]


def _normalize(rfc4514: str) -> str:
    return re.sub(r"\s+", " ", str(rfc4514 or "")).strip()


def _extract_cn(rfc4514: str) -> str:
    m = re.search(r"CN=([^,+]+)", str(rfc4514 or ""), re.IGNORECASE)
    if m:
        return m.group(1).strip()[:60]
    m = re.search(r"O=([^,+]+)", str(rfc4514 or ""), re.IGNORECASE)
    return m.group(1).strip()[:60] if m else str(rfc4514 or "")[:60]


def _port_node_type(port: int) -> str:
    if port in _DATA_STORE_PORTS:
        return "data_store"
    if port in _INFRA_PORTS:
        return "infra"
    return "service"


def _exposure_for_port(port: int, key_type: str = "") -> float:
    base = _PORT_EXPOSURE_USD.get(port, _DEFAULT_EXPOSURE_USD)
    kt = (key_type or "").lower()
    if "rsa" in kt or "dh" in kt or "ecc" in kt or "ec" in kt:
        return base * 1.2
    if "ml-kem" in kt or "kyber" in kt or "pq" in kt:
        return base * 0.05
    return base


# ── Persistent custom edge store ───────────────────────────────────────────────

def _db():
    from db import get_connection
    return get_connection()


def _ensure_custom_edge_table() -> None:
    with closing(_db()) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS blast_radius_custom_edges (
                id          TEXT PRIMARY KEY,
                org_id      TEXT NOT NULL,
                from_node   TEXT NOT NULL,
                to_node     TEXT NOT NULL,
                from_label  TEXT NOT NULL DEFAULT '',
                to_label    TEXT NOT NULL DEFAULT '',
                notes       TEXT NOT NULL DEFAULT '',
                created_at  TEXT NOT NULL
            )
        """)
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_br_edge_uniq "
            "ON blast_radius_custom_edges(org_id, from_node, to_node)"
        )
        conn.commit()


def add_custom_edge(
    org_id: str,
    from_node: str,
    to_node: str,
    from_label: str = "",
    to_label: str = "",
    notes: str = "",
) -> Dict[str, Any]:
    _ensure_custom_edge_table()
    edge_id = secrets.token_urlsafe(10)
    now_iso = datetime.now(timezone.utc).isoformat()
    with closing(_db()) as conn:
        conn.execute(
            """INSERT OR REPLACE INTO blast_radius_custom_edges
               (id, org_id, from_node, to_node, from_label, to_label, notes, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (edge_id, org_id, from_node, to_node,
             from_label or "", to_label or "", notes or "", now_iso),
        )
        conn.commit()
    return {
        "id": edge_id, "from_node": from_node, "to_node": to_node,
        "from_label": from_label, "to_label": to_label,
        "notes": notes, "created_at": now_iso,
    }


def delete_custom_edge(edge_id: str, org_id: str) -> bool:
    _ensure_custom_edge_table()
    with closing(_db()) as conn:
        cur = conn.execute(
            "DELETE FROM blast_radius_custom_edges WHERE id = ? AND org_id = ?",
            (edge_id, org_id),
        )
        conn.commit()
    return cur.rowcount > 0


def list_custom_edges(org_id: str) -> List[Dict[str, Any]]:
    _ensure_custom_edge_table()
    with closing(_db()) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM blast_radius_custom_edges WHERE org_id = ? ORDER BY created_at DESC",
            (org_id,),
        ).fetchall()
    return [dict(r) for r in rows]


# ── Core graph builder ─────────────────────────────────────────────────────────

def build_blast_radius_graph(
    scan_results_list: List[List[Dict[str, Any]]],
    org_id: str = "",
) -> Dict[str, Any]:
    """
    Build a cryptographic dependency graph from multiple scan result sets.
    Merges user-defined custom edges from the database.

    scan_results_list: list of per-scan result arrays. Each element is a
    list of per-host result dicts with cert_chain, host, port, risk fields.

    Returns {nodes, edges, meta}.
    """
    nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, str]] = []
    edge_set: Set[Tuple[str, str]] = set()

    def add_node(nid: str, ntype: str, label: str, **extra: Any) -> None:
        if nid not in nodes:
            nodes[nid] = {"id": nid, "type": ntype, "label": label[:60], **extra}

    def add_edge(fid: str, tid: str, etype: str) -> None:
        k = (fid, tid)
        if k not in edge_set and fid != tid:
            edge_set.add(k)
            edges.append({"from": fid, "to": tid, "type": etype})

    for results in scan_results_list:
        for r in (results or []):
            if r.get("error"):
                continue
            host = str(r.get("host") or "")
            port = int(r.get("port") or 443)
            if not host:
                continue

            asset_key = f"{host}:{port}"
            svc_id = _node_id(asset_key)
            svc_type = _port_node_type(port)
            key_type = str(r.get("cert_key_type") or r.get("key_type") or "")
            add_node(
                svc_id, svc_type, asset_key,
                asset_key=asset_key,
                port=port,
                key_type=key_type,
                key_bits=int(r.get("cert_key_bits") or r.get("key_bits") or 0),
                tls_version=str(r.get("tls_version") or ""),
                risk_level=str(r.get("quantum_risk_level") or r.get("risk_level") or "unknown"),
                risk_score=int(r.get("quantum_risk_score") or 0),
                exposure_usd=_exposure_for_port(port, key_type),
            )

            cert_chain: List[Dict[str, Any]] = r.get("cert_chain") or []
            leaf_cert_id: Optional[str] = None

            for i, cert in enumerate(cert_chain):
                subj = _normalize(str(cert.get("subject") or ""))
                issuer = _normalize(str(cert.get("issuer") or ""))
                if not subj:
                    continue

                cert_id = _node_id(subj)
                cn = _extract_cn(subj)
                is_leaf = (i == 0)
                is_self_signed = (subj == issuer) or not issuer

                if is_self_signed:
                    ntype = "root_ca"
                elif is_leaf:
                    ntype = "leaf_cert"
                else:
                    ntype = "intermediate_ca"

                add_node(
                    cert_id, ntype, cn,
                    subject=subj,
                    issuer=issuer,
                    key_type=str(cert.get("key_type") or ""),
                    key_bits=int(cert.get("key_bits") or 0),
                    is_self_signed=is_self_signed,
                    exposure_usd=0.0,
                )

                if is_leaf:
                    leaf_cert_id = cert_id

                if not is_self_signed and issuer:
                    iss_id = _node_id(issuer)
                    if iss_id not in nodes:
                        add_node(iss_id, "intermediate_ca", _extract_cn(issuer),
                                 subject=issuer, issuer="", key_type="", key_bits=0,
                                 is_self_signed=False, exposure_usd=0.0)
                    add_edge(iss_id, cert_id, "ca_signs")

            if leaf_cert_id:
                add_edge(leaf_cert_id, svc_id, "cert_binds")

    # Promote nodes with no incoming edges to root_ca if they look like CAs
    incoming: Set[str] = {e["to"] for e in edges}
    for nid, node in nodes.items():
        if nid not in incoming and node["type"] == "intermediate_ca":
            node["type"] = "root_ca"

    # Merge custom dependency edges
    if org_id:
        try:
            for ce in list_custom_edges(org_id):
                fn, tn = ce["from_node"], ce["to_node"]
                # Auto-create phantom nodes for custom edges if not already present
                if fn not in nodes:
                    add_node(fn, "service", ce.get("from_label") or fn,
                             exposure_usd=_DEFAULT_EXPOSURE_USD)
                if tn not in nodes:
                    add_node(tn, "service", ce.get("to_label") or tn,
                             exposure_usd=_DEFAULT_EXPOSURE_USD)
                add_edge(fn, tn, "depends_on")
        except Exception:
            pass

    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "meta": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "root_ca_count":        sum(1 for n in nodes.values() if n["type"] == "root_ca"),
            "intermediate_ca_count": sum(1 for n in nodes.values() if n["type"] == "intermediate_ca"),
            "leaf_cert_count":       sum(1 for n in nodes.values() if n["type"] == "leaf_cert"),
            "service_count":         sum(1 for n in nodes.values() if n["type"] == "service"),
            "data_store_count":      sum(1 for n in nodes.values() if n["type"] == "data_store"),
        },
    }


# ── BFS cascade simulation with HNDL exposure ─────────────────────────────────

def compute_blast_radius(
    node_id: str,
    graph: Dict[str, Any],
    q_day_year: int = 2031,
) -> Dict[str, Any]:
    """
    BFS from node_id following edges downward (toward services/data stores).
    Returns all affected node IDs, summary stats, and HNDL financial exposure.
    """
    by_id: Dict[str, Dict[str, Any]] = {n["id"]: n for n in graph.get("nodes", [])}
    fwd: Dict[str, List[str]] = {}
    for e in graph.get("edges", []):
        fwd.setdefault(e["from"], []).append(e["to"])

    visited: Set[str] = set()
    queue = [node_id]
    while queue:
        cur = queue.pop(0)
        if cur in visited:
            continue
        visited.add(cur)
        queue.extend(fwd.get(cur, []))

    affected = [by_id[nid] for nid in visited if nid in by_id]
    services = [n for n in affected if n["type"] in ("service", "data_store", "infra")]
    data_stores = [n for n in affected if n["type"] == "data_store"]
    origin = by_id.get(node_id, {})

    # HNDL exposure calculation using Q-Day probability
    q_day_prob = _q_day_prob(origin.get("key_type", ""), q_day_year)
    total_exposure = sum(
        (n.get("exposure_usd") or 0) * q_day_prob
        for n in services
    )

    severity = (
        "critical" if total_exposure >= 1_000_000 or data_stores or len(services) >= 10
        else "high"   if total_exposure >= 200_000 or len(services) >= 3
        else "medium" if services
        else "low"
    )

    def _fmt_usd(v: float) -> str:
        if v >= 1_000_000:
            return f"${v / 1_000_000:.1f}M"
        if v >= 1_000:
            return f"${v / 1_000:.0f}K"
        return f"${v:.0f}"

    return {
        "origin_node": origin,
        "affected_node_ids": list(visited),
        "affected_count": len(affected),
        "service_count": len(services),
        "data_store_count": len(data_stores),
        "affected_services": [
            n.get("asset_key") or n.get("label", "") for n in services
        ],
        "severity": severity,
        "hndl_exposure_usd": round(total_exposure, 2),
        "hndl_exposure_fmt": _fmt_usd(total_exposure),
        "q_day_year": q_day_year,
        "q_day_prob": round(q_day_prob, 3),
        "summary": (
            f"Breaking '{origin.get('label', node_id)}' exposes "
            f"{len(services)} service{'s' if len(services) != 1 else ''}"
            + (f" including {len(data_stores)} data store{'s' if len(data_stores) != 1 else ''}" if data_stores else "")
            + f". HNDL exposure: {_fmt_usd(total_exposure)} at Q-Day {q_day_year}."
        ),
    }


def export_graph_report(graph: Dict[str, Any], org_id: str = "") -> Dict[str, Any]:
    """Export the full graph as a structured report for download or archival."""
    return {
        "report_type": "blast_radius_graph",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "org_id": org_id,
        "meta": graph.get("meta", {}),
        "nodes": graph.get("nodes", []),
        "edges": graph.get("edges", []),
    }


# ── Q-Day probability (simplified — mirrors hndl.py) ─────────────────────────

_Q_DAY_PROBS_BR: Dict[str, Dict[int, float]] = {
    "rsa": {2027: 0.01, 2028: 0.03, 2029: 0.07, 2030: 0.15, 2031: 0.28, 2032: 0.45, 2033: 0.65, 2034: 0.80, 2035: 0.92},
    "ec":  {2027: 0.02, 2028: 0.05, 2029: 0.12, 2030: 0.25, 2031: 0.42, 2032: 0.62, 2033: 0.78, 2034: 0.90, 2035: 0.96},
    "pq": {2027: 0.00, 2028: 0.00, 2029: 0.00, 2030: 0.00, 2031: 0.01, 2032: 0.01, 2033: 0.02, 2034: 0.02, 2035: 0.02},
}


def _q_day_prob(key_type: str, q_day_year: int) -> float:
    kt = (key_type or "").lower()
    if "ml-kem" in kt or "kyber" in kt or "slh" in kt or "dilithium" in kt:
        table = _Q_DAY_PROBS_BR["pq"]
    elif "ec" in kt or "ecdsa" in kt or "ecdh" in kt:
        table = _Q_DAY_PROBS_BR["ec"]
    else:
        table = _Q_DAY_PROBS_BR["rsa"]

    years = sorted(table.keys())
    if q_day_year <= years[0]:
        return table[years[0]]
    if q_day_year >= years[-1]:
        return table[years[-1]]
    for i in range(len(years) - 1):
        y0, y1 = years[i], years[i + 1]
        if y0 <= q_day_year <= y1:
            t = (q_day_year - y0) / (y1 - y0)
            return table[y0] + t * (table[y1] - table[y0])
    return 0.0
