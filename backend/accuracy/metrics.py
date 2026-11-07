"""Compare Morrow's scan output with reference labels and score it per protocol and attribute.

Kept free of network and Morrow imports so the scoring itself is unit tested in normal CI
(test_accuracy_metrics.py). The live part is accuracy/run_accuracy.py.

Two kinds of attribute:

* **binary** -- "does the endpoint offer TLS 1.0", "is hybrid PQ key exchange supported". Scored on
  the positive class: precision = TP / (TP + FP), recall = TP / (TP + FN), where a positive the
  scanner gave no answer for counts as a miss (FN). An endpoint whose *label* is unknown is left out.
* **value** -- certificate key type, key size, signature algorithm, SSH algorithm lists. Precision
  is the share of the answers Morrow gave that are right; recall is the share of the labelled
  endpoints Morrow got right. An empty answer lowers recall only; a wrong answer lowers both.

Python 3.11 compatible.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

TLS_VERSIONS = ("TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3")

#: (attribute, kind) per protocol, in the order the report prints them.
TLS_ATTRIBUTES: Tuple[Tuple[str, str], ...] = tuple(
    [(f"offers_{v}", "binary") for v in TLS_VERSIONS]
    + [
        ("pq_hybrid", "binary"),
        ("cert_key_type", "value"),
        ("cert_key_bits", "value"),
        ("sig_algorithm", "value"),
        ("cert_quantum_vulnerable", "binary"),
        ("hndl_vulnerable", "binary"),
    ]
)
SSH_ATTRIBUTES: Tuple[Tuple[str, str], ...] = (
    ("pq_hybrid", "binary"),
    ("kex_algorithms", "value"),
    ("host_key_algorithms", "value"),
    ("sha1_kex_offered", "binary"),
    ("hostkey_quantum_vulnerable", "binary"),
    ("hndl_vulnerable", "binary"),
)
ATTRIBUTES = {"tls": TLS_ATTRIBUTES, "ssh": SSH_ATTRIBUTES}


def norm_sig(name: Optional[str]) -> Optional[str]:
    """OpenSSL says "ecdsa-with-SHA256" / "rsassaPss"; cryptography says "ecdsa-with-SHA256" /
    "RSASSA-PSS". Compare case- and punctuation-insensitively."""
    if not name:
        return None
    return re.sub(r"[^a-z0-9]", "", str(name).lower()) or None


def tls_truth(labels: Dict[str, Any]) -> Dict[str, Any]:
    v = labels.get("tls_versions") or {}
    out: Dict[str, Any] = {f"offers_{k}": v.get(k) for k in TLS_VERSIONS}
    out["pq_hybrid"] = labels.get("pq_hybrid")
    out["cert_key_type"] = labels.get("cert_key_type")
    out["cert_key_bits"] = labels.get("cert_key_bits")
    out["sig_algorithm"] = norm_sig(labels.get("sig_algorithm"))
    out["cert_quantum_vulnerable"] = labels.get("cert_quantum_vulnerable")
    out["hndl_vulnerable"] = labels.get("hndl_vulnerable")
    return out


def tls_prediction(facts: Dict[str, Any]) -> Dict[str, Any]:
    """What Morrow's scan_host() said, in the label vocabulary. None = Morrow gave no answer."""
    out: Dict[str, Any] = {}
    ok = facts.get("scan_status") == "ok"
    supported = set(facts.get("tls_supported_versions") or [])
    # Morrow names the versions it probed; anything it did not probe is no answer.
    probed = set((facts.get("tls_support_map") or {}).keys())
    for v in TLS_VERSIONS:
        out[f"offers_{v}"] = (v in supported) if (v in probed or supported) else None
    if facts.get("key_exchange_observed"):
        out["pq_hybrid"] = facts.get("key_exchange_family") in ("pq_hybrid", "pq_pure")
    else:
        out["pq_hybrid"] = None
    out["cert_key_type"] = (facts.get("key_type") or None) if ok else None
    out["cert_key_bits"] = (int(facts.get("key_bits") or 0) or None) if ok else None
    out["sig_algorithm"] = norm_sig(facts.get("sig_algorithm")) if ok else None
    dep = facts.get("classical_crypto_dependency")
    out["cert_quantum_vulnerable"] = bool(dep) if ok and dep is not None else None
    hndl = str(facts.get("harvest_now_decrypt_later_risk") or "").lower()
    out["hndl_vulnerable"] = {"critical": True, "high": True, "medium": True, "low": False, "none": False}.get(hndl)
    return out


def ssh_truth(labels: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "pq_hybrid": labels.get("pq_hybrid"),
        "kex_algorithms": tuple(labels.get("kex_algorithms") or ()) or None,
        "host_key_algorithms": tuple(labels.get("host_key_algorithms") or ()) or None,
        "sha1_kex_offered": labels.get("sha1_kex_offered"),
        "hostkey_quantum_vulnerable": labels.get("hostkey_quantum_vulnerable"),
        "hndl_vulnerable": labels.get("hndl_vulnerable"),
    }


def ssh_prediction(result: Dict[str, Any]) -> Dict[str, Any]:
    if result.get("error"):
        return {k: None for k, _ in SSH_ATTRIBUTES}
    rules = {str(f.get("rule_id") or "") for f in result.get("findings") or []}
    return {
        "pq_hybrid": bool(result.get("pq_ready")),
        "kex_algorithms": tuple(result.get("kex_algorithms") or ()) or None,
        "host_key_algorithms": tuple(result.get("host_key_algorithms") or ()) or None,
        "sha1_kex_offered": "SSH_CRITICAL_KEX" in rules,
        "hostkey_quantum_vulnerable": "SSH_QUANTUM_VULNERABLE_HOST_KEY" in rules,
        "hndl_vulnerable": "SSH_NO_MORROW_KEX" in rules,
    }


def truth_and_prediction(protocol: str, labels: Dict[str, Any], scan: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    if protocol == "tls":
        return tls_truth(labels), tls_prediction(scan)
    return ssh_truth(labels), ssh_prediction(scan)


def _ratio(n: int, d: int) -> Optional[float]:
    return round(n / d, 4) if d else None


def _f1(p: Optional[float], r: Optional[float]) -> Optional[float]:
    if p is None or r is None or (p + r) == 0:
        return None if p is None or r is None else 0.0
    return round(2 * p * r / (p + r), 4)


def score(rows: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """rows: {"id", "protocol", "truth": {...}, "pred": {...}} -> per protocol/attribute metrics
    plus the list of every disagreement."""
    rows = list(rows)
    metrics: Dict[str, Dict[str, Dict[str, Any]]] = {}
    misses: List[Dict[str, Any]] = []
    for proto, attrs in ATTRIBUTES.items():
        prow = [r for r in rows if r["protocol"] == proto]
        if not prow:
            continue
        metrics[proto] = {}
        for attr, kind in attrs:
            tp = fp = fn = tn = abstain = correct = answered = labelled = 0
            for r in prow:
                t = r["truth"].get(attr)
                p = r["pred"].get(attr)
                if t is None:
                    continue
                labelled += 1
                if p is None:
                    abstain += 1
                if kind == "binary":
                    if t and p:
                        tp += 1
                    elif t and not p:
                        fn += 1
                    elif not t and p:
                        fp += 1
                    elif p is not None:
                        tn += 1
                    wrong = (p is None) or (bool(p) != bool(t))
                else:
                    if p is not None:
                        answered += 1
                        if p == t:
                            correct += 1
                    wrong = p != t
                if wrong:
                    misses.append({"id": r["id"], "protocol": proto, "attribute": attr,
                                   "label": t, "morrow": p})
            if kind == "binary":
                prec, rec = _ratio(tp, tp + fp), _ratio(tp, tp + fn)
                m = {"kind": kind, "n": labelled, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
                     "no_answer": abstain, "precision": prec, "recall": rec, "f1": _f1(prec, rec),
                     "accuracy": _ratio(tp + tn, labelled)}
            else:
                prec, rec = _ratio(correct, answered), _ratio(correct, labelled)
                m = {"kind": kind, "n": labelled, "correct": correct, "answered": answered,
                     "no_answer": abstain, "precision": prec, "recall": rec, "f1": _f1(prec, rec),
                     "accuracy": rec}
            metrics[proto][attr] = m
    return {"metrics": metrics, "misses": misses}


def label_drift(old: Iterable[Dict[str, Any]], new: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Attributes whose reference label changed between two labelling runs.

    The weekly job relabels before it scans, so a disagreement it reports is measured against this
    week's configuration. This list is the other half: endpoints that changed since the committed
    dataset was labelled -- "endpoint changed", not "scanner wrong"."""
    old_by = {r["id"]: r for r in old}
    out: List[Dict[str, Any]] = []
    for r in new:
        o = old_by.get(r["id"])
        if not o:
            continue
        if bool(o.get("reachable")) != bool(r.get("reachable")):
            out.append({"id": r["id"], "attribute": "reachable", "was": o.get("reachable"), "now": r.get("reachable")})
            continue
        if not r.get("reachable"):
            continue
        conv = tls_truth if r["protocol"] == "tls" else ssh_truth
        a, b = conv(o["labels"]), conv(r["labels"])
        for k in a:
            if a[k] is not None and b[k] is not None and a[k] != b[k]:
                out.append({"id": r["id"], "attribute": k, "was": a[k], "now": b[k]})
    return out


def markdown_table(metrics: Dict[str, Dict[str, Dict[str, Any]]]) -> str:
    def pct(x: Optional[float]) -> str:
        return "n/a" if x is None else f"{100 * x:.1f}%"

    lines = ["| Protocol | Attribute | n | Precision | Recall | F1 | Misses |",
             "|---|---|---:|---:|---:|---:|---:|"]
    for proto, attrs in metrics.items():
        for attr, m in attrs.items():
            # Every labelled endpoint Morrow did not get right: wrong answers and no answers.
            miss = m["n"] - (m["tp"] + m["tn"] if m["kind"] == "binary" else m["correct"])
            lines.append(f"| {proto.upper()} | `{attr}` | {m['n']} | {pct(m['precision'])} | "
                         f"{pct(m['recall'])} | {pct(m['f1'])} | {miss} |")
    return "\n".join(lines)
