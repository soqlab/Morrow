"""
Cross-Organization Quantum Contagion Graph

Maps cryptographic dependencies BETWEEN organizations through shared CAs, as
observed in your own scans. If a CA key were broken by a quantum computer,
every organization whose observed certificates chain to that CA would be
exposed at the same time.

Data sources:
  - Your scan data (cert chains grouped by registrable domain)
  - Certificate issuer names from those chains

Not included: CA market shares or estimates of how many organizations a CA
serves worldwide. The platform has no sourced figures for them, so only
organizations observed in your scans are counted.

Node types in the contagion graph:
  root_ca  — a certificate authority (the contagion source)
  org      — an organization (grouped by eTLD+1 domain)

Edges:
  issues_to — CA issued a cert to this org
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from typing import Any, Dict, List, Set, Tuple

from services.model_basis import model_basis as _model_basis


def contagion_model_basis() -> Dict[str, Any]:
    return _model_basis(
        kind="model",
        summary=(
            "The graph links organizations to CAs using only certificate chains in your scans; it does not "
            "estimate CA market share or how many organizations exist outside your scan data."
        ),
        assumptions=[
            "Organizations are grouped by registrable domain (eTLD+1, best effort without the Public Suffix List).",
            "Every certificate after the leaf, and any self-signed certificate, is treated as a CA node.",
            "A broken CA key is assumed to expose every organization whose observed chain includes that CA.",
        ],
        sources=[],
        as_of="2026-09",
    )


def _node_id(label: str) -> str:
    return hashlib.md5(label.encode(), usedforsecurity=False).hexdigest()[:14]


def _extract_cn(rfc4514: str) -> str:
    m = re.search(r"CN=([^,+]+)", str(rfc4514 or ""), re.IGNORECASE)
    if m:
        return m.group(1).strip()[:80]
    m = re.search(r"O=([^,+]+)", str(rfc4514 or ""), re.IGNORECASE)
    return m.group(1).strip()[:80] if m else str(rfc4514 or "")[:80]


def _extract_etld1(host: str) -> str:
    """Extract eTLD+1 from hostname (best-effort without a PSL library)."""
    host = (host or "").lower().strip().split(":")[0]
    parts = host.split(".")
    if len(parts) >= 2:
        # Handle known ccSLD patterns (.co.uk, .com.au, .org.uk, etc.)
        if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "gov", "edu", "ac"):
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    return host


def _infer_org_name(etld1: str) -> str:
    """Convert eTLD+1 to a readable org name."""
    domain = etld1.split(".")[0] if "." in etld1 else etld1
    return domain.replace("-", " ").title()


def build_contagion_graph(
    scan_results_list: List[List[Dict[str, Any]]],
) -> Dict[str, Any]:
    """
    Build a cross-organization contagion graph.

    Groups scanned hosts by eTLD+1 domain (= organization) and links
    each org to the CAs that issued their certificates.

    Returns {nodes, edges, meta, model_basis}.
    """
    nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, Any]] = []
    edge_set: Set[Tuple[str, str]] = set()

    # ca_id → set of org_ids
    ca_to_orgs: Dict[str, Set[str]] = defaultdict(set)

    def add_node(nid: str, ntype: str, label: str, **extra: Any) -> None:
        if nid not in nodes:
            nodes[nid] = {"id": nid, "type": ntype, "label": label[:80], **extra}

    def add_edge(fid: str, tid: str, etype: str, **extra: Any) -> None:
        k = (fid, tid)
        if k not in edge_set and fid != tid:
            edge_set.add(k)
            edges.append({"from": fid, "to": tid, "type": etype, **extra})

    for results in scan_results_list:
        for r in (results or []):
            if r.get("error"):
                continue
            host = str(r.get("host") or "")
            if not host:
                continue

            etld1 = _extract_etld1(host)
            org_id = _node_id(f"org:{etld1}")
            org_name = _infer_org_name(etld1)

            add_node(org_id, "org", org_name,
                     etld1=etld1, host_count=0, key_type="",
                     key_bits=0, risk_level="unknown")
            nodes[org_id]["host_count"] = nodes[org_id].get("host_count", 0) + 1
            nodes[org_id]["key_type"] = str(r.get("cert_key_type") or r.get("key_type") or "")
            nodes[org_id]["key_bits"] = int(r.get("cert_key_bits") or r.get("key_bits") or 0)
            nodes[org_id]["risk_level"] = str(r.get("quantum_risk_level") or "unknown")

            cert_chain: List[Dict[str, Any]] = r.get("cert_chain") or []
            for i, cert in enumerate(cert_chain):
                subj = str(cert.get("subject") or "")
                issuer = str(cert.get("issuer") or "")
                is_self_signed = not issuer or subj == issuer
                is_root = is_self_signed or i == len(cert_chain) - 1

                if is_root or i > 0:  # it's a CA cert
                    ca_label = _extract_cn(subj)
                    ca_id = _node_id(f"ca:{subj}")

                    add_node(ca_id, "root_ca", ca_label,
                             subject=subj,
                             key_type=str(cert.get("key_type") or ""),
                             key_bits=int(cert.get("key_bits") or 0),
                             is_self_signed=is_self_signed)

                    add_edge(ca_id, org_id, "issues_to",
                             cert_cn=_extract_cn(str(cert.get("subject") or "")))
                    ca_to_orgs[ca_id].add(org_id)

    for ca_id, org_set in ca_to_orgs.items():
        if ca_id in nodes:
            nodes[ca_id]["observed_org_count"] = len(org_set)
            nodes[ca_id]["total_org_reach"] = len(org_set)

    ca_nodes = [n for n in nodes.values() if n["type"] == "root_ca"]
    org_nodes = [n for n in nodes.values() if n["type"] == "org"]

    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "ca_to_orgs": {ca: list(orgs) for ca, orgs in ca_to_orgs.items()},
        "meta": {
            "ca_count": len(ca_nodes),
            "org_count": len(org_nodes),
            "edge_count": len(edges),
            "most_connected_ca": (
                max(ca_nodes, key=lambda n: n.get("observed_org_count", 0))["label"]
                if ca_nodes else None
            ),
        },
        "model_basis": contagion_model_basis(),
    }


def compute_contagion(
    ca_node_id: str,
    contagion_graph: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Simulate the contagion spreading from a broken CA node.
    Returns all observed organizations exposed at the same time.
    """
    by_id: Dict[str, Dict[str, Any]] = {n["id"]: n for n in contagion_graph.get("nodes", [])}
    fwd: Dict[str, List[str]] = defaultdict(list)
    for e in contagion_graph.get("edges", []):
        fwd[e["from"]].append(e["to"])

    origin = by_id.get(ca_node_id, {})
    if not origin:
        return {"error": f"CA node {ca_node_id} not found", "model_basis": contagion_model_basis()}

    visited: Set[str] = set()
    queue = [ca_node_id]
    while queue:
        cur = queue.pop(0)
        if cur in visited: continue
        visited.add(cur)
        queue.extend(fwd.get(cur, []))

    affected = [by_id[nid] for nid in visited if nid in by_id]
    orgs = [n for n in affected if n["type"] == "org"]
    sub_cas = [n for n in affected if n["type"] == "root_ca" and n["id"] != ca_node_id]

    return {
        "origin_ca": origin,
        "affected_org_ids": [n["id"] for n in orgs],
        "affected_orgs": [{"id": n["id"], "label": n["label"],
                           "etld1": n.get("etld1", ""),
                           "host_count": n.get("host_count", 1),
                           "risk_level": n.get("risk_level", "unknown")} for n in orgs],
        "affected_sub_cas": [n["label"] for n in sub_cas],
        "observed_org_count": len(orgs),
        "estimated_global_org_count": None,
        "simultaneous_response_window_hours": None,
        "severity": "critical" if len(orgs) >= 10 else "high",
        "summary": (
            f"Breaking '{origin.get('label', ca_node_id)}' would expose {len(orgs)} "
            f"organization{'s' if len(orgs) != 1 else ''} observed in your scans at the same time."
        ),
        "model_basis": contagion_model_basis(),
    }
