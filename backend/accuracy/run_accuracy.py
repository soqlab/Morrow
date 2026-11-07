"""Scan every labelled endpoint with Morrow's real scanners and score them against the labels.

    cd backend
    python -m accuracy.run_accuracy                      # all endpoints in accuracy/endpoints.jsonl
    python -m accuracy.run_accuracy --only github.com    # a subset
    python -m accuracy.run_accuracy --github             # also emit GitHub warning annotations

Network only, and never part of the normal test run (see test_accuracy_live.py for the opt-in
pytest entry point). It calls scanner.scan_host() and ssh_scanner.scan_ssh() exactly as POST /scan
does, with one change: the OCSP/CRL reachability probes are switched off. They send HTTP requests to
the certificate authority, not to the endpoint, and no attribute measured here depends on them, so
leaving them on would only add load on third parties.

Pacing: one scan per host at a time (Morrow's own probes inside a scan are sequential), at most
--workers different hosts in flight, and a pause between hosts.

Writes accuracy/results/latest.json (metrics, every disagreement, Morrow's answer per endpoint) and
prints the per-protocol table. Exit status is 0 whatever the numbers are: the internet changes under
this suite, so the weekly job reports and warns, it does not fail.

Python 3.11 compatible.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime as _dt
import json
import os
import platform
import ssl
import sys
import threading
import time
from typing import Any, Dict, List, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from accuracy import metrics as M  # noqa: E402

DATASET = os.path.join(HERE, "endpoints.jsonl")
RESULTS_DIR = os.path.join(HERE, "results")
PAUSE_BETWEEN_HOSTS = 0.5


def load_dataset(path: str = DATASET, only: str = "") -> List[Dict[str, Any]]:
    wanted = {h.strip().lower() for h in only.split(",") if h.strip()}
    optout = set()
    optout_path = os.path.join(HERE, "optout.txt")
    if os.path.exists(optout_path):
        with open(optout_path, encoding="utf-8") as fh:
            optout = {ln.split("#", 1)[0].strip().lower() for ln in fh if ln.split("#", 1)[0].strip()}
    rows = []
    with open(path, encoding="utf-8") as fh:
        for ln in fh:
            if not ln.strip():
                continue
            r = json.loads(ln)
            if not r.get("reachable") or r["host"].lower() in optout:
                continue
            if wanted and r["host"].lower() not in wanted:
                continue
            rows.append(r)
    return rows


def _quiet_scanner():
    """Import the scanners with revocation probes disabled and domain-scope enforcement off."""
    os.environ.pop("MORROW_SCAN_REQUIRE_VERIFIED_DOMAINS", None)
    import scanner
    import ssh_scanner

    scanner._probe_revocation_endpoints = lambda *a, **k: {"ocsp_reachability": [], "crl_reachability": []}
    return scanner, ssh_scanner


def scan_one(rec: Dict[str, Any]) -> Dict[str, Any]:
    scanner, ssh_scanner = _quiet_scanner()
    started = time.time()
    try:
        if rec["protocol"] == "tls":
            out = scanner.scan_host(rec["host"], int(rec["port"]))
        else:
            out = ssh_scanner.scan_ssh(rec["host"], int(rec["port"]))
    except Exception as exc:  # a crash is a result too: record it, never abort the run
        out = {"error": f"{type(exc).__name__}: {exc}", "scan_status": "crashed"}
    out["_elapsed_s"] = round(time.time() - started, 1)
    time.sleep(PAUSE_BETWEEN_HOSTS)
    return out


_KEEP_TLS = ("scan_status", "error", "tls_version", "tls_supported_versions", "tls_support_map", "tls_probe_errors",
             "key_exchange", "key_exchange_family", "key_exchange_observed",
             "key_exchange_unobservable_reason", "key_exchange_hello_retry", "key_type", "key_bits",
             "key_curve", "sig_algorithm", "classical_crypto_dependency",
             "harvest_now_decrypt_later_risk", "subject", "_elapsed_s")
_KEEP_SSH = ("error", "banner", "kex_algorithms", "host_key_algorithms", "pq_ready", "pq_hybrid_kex",
             "findings", "_elapsed_s")


def _kept(scan: Dict[str, Any], keep: tuple) -> Dict[str, Any]:
    out = {k: scan.get(k) for k in keep}
    if "findings" in out:       # rule ids are what scoring reads; the prose is not needed
        out["findings"] = [{"rule_id": f.get("rule_id")} for f in (out["findings"] or [])]
    return out


def _timeouts(scan: Dict[str, Any]) -> int:
    """How many of a scan's probes ended in a timeout."""
    texts = [str(scan.get("error") or ""), str(scan.get("key_exchange_unobservable_reason") or "")]
    texts += [str(v) for v in (scan.get("tls_probe_errors") or {}).values()]
    return sum(1 for t in texts if "timed out" in t.lower())


def site_key(host: str) -> str:
    """Hosts that are very likely the same operator's servers share a key: the last two labels
    (three for a two-letter country code under a short second level, e.g. bbc.co.uk). The 24
    badssl.com subdomains are one machine; scanning them in parallel was six connections to one
    server at once, which is both impolite and the cause of the timeouts in the first runs."""
    labels = host.lower().rstrip(".").split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and len(labels[-2]) <= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def run(rows: List[Dict[str, Any]], workers: int = 6) -> Dict[str, Any]:
    scans: Dict[str, Dict[str, Any]] = {}
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for r in rows:
        groups.setdefault(site_key(r["host"]), []).append(r)
    lock = threading.Lock()
    done = [0]

    def scan_group(members: List[Dict[str, Any]]) -> None:
        # One site at a time per worker: never two connections to the same operator at once.
        for r in members:
            out = scan_one(r)
            with lock:
                scans[r["id"]] = out
                done[0] += 1
                print(f"[{done[0]}/{len(rows)}] {r['id']} ({out.get('_elapsed_s')}s)", file=sys.stderr, flush=True)

    # Largest groups first, so one long group does not finish alone at the end.
    ordered = sorted(groups.values(), key=len, reverse=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        list(pool.map(scan_group, ordered))

    # One retry, after everything else, for a scan where any probe timed out: a dropped packet on a
    # busy network is not a property of the scanner or the endpoint. The retry runs with one worker
    # (nothing else in flight) and its result replaces the first only if fewer probes timed out.
    retried: List[str] = []
    for r in rows:
        if _timeouts(scans[r["id"]]):
            again = scan_one(r)
            if _timeouts(again) < _timeouts(scans[r["id"]]):
                scans[r["id"]] = again
            retried.append(r["id"])
            print(f"[retry] {r['id']} ({again.get('_elapsed_s')}s)", file=sys.stderr, flush=True)

    return assemble(rows, scans, retried=retried)


#: Failures of the scanning host itself, not of the scanner or the endpoint.
_ENVIRONMENT_ERRORS = ("temporary failure in name resolution", "name or service not known",
                       "network is unreachable")


def environment_failure(scan: Dict[str, Any]) -> bool:
    texts = [str(scan.get("error") or ""), str(scan.get("key_exchange_unobservable_reason") or "")]
    texts += [str(v) for v in (scan.get("tls_probe_errors") or {}).values()]
    return any(e in t.lower() for t in texts for e in _ENVIRONMENT_ERRORS)


def scans_from_result(result: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """The per-endpoint scans a results file kept, enough to score them again."""
    out: Dict[str, Dict[str, Any]] = {}
    for e in result.get("endpoints") or []:
        scan = dict(e.get("morrow") or {})
        if e["id"].startswith("tls:") and "tls_support_map" not in scan:
            # Older results files did not keep the map; it is all four versions whenever the
            # version probes ran, which is exactly when either of these is non-empty.
            sup = set(scan.get("tls_supported_versions") or [])
            if sup or scan.get("tls_probe_errors"):
                scan["tls_support_map"] = {v: v in sup for v in M.TLS_VERSIONS}
        out[e["id"]] = scan
    return out


def rescan_environment_failures(rows: List[Dict[str, Any]], previous: Dict[str, Any]) -> Dict[str, Any]:
    """Score a previous run again, rescanning only the endpoints whose scan failed because the
    scanning host lost DNS or its route (an outage on our side). Every other endpoint keeps its
    original scan; the rescanned ids are recorded in the result."""
    scans = scans_from_result(previous)
    rescanned: List[str] = []
    for r in rows:
        prev = scans.get(r["id"])
        # A row that cannot be rescored (missing, or an SSH row from a results file that did not
        # keep its findings) is rescanned too.
        unscorable = prev is None or (r["protocol"] == "ssh" and "findings" not in prev)
        if unscorable or environment_failure(prev):
            scans[r["id"]] = scan_one(r)
            rescanned.append(r["id"])
            print(f"[rescan] {r['id']} ({scans[r['id']].get('_elapsed_s')}s)", file=sys.stderr, flush=True)
    return assemble(rows, scans, retried=list(previous.get("retried_after_timeout") or []),
                    rescanned=rescanned, first_run_at=previous.get("generated_at"))


def assemble(rows: List[Dict[str, Any]], scans: Dict[str, Dict[str, Any]], retried: List[str],
             rescanned: Optional[List[str]] = None, first_run_at: Optional[str] = None) -> Dict[str, Any]:
    scored_rows = []
    endpoints = []
    for r in rows:
        scan = scans[r["id"]]
        truth, pred = M.truth_and_prediction(r["protocol"], r["labels"], scan)
        scored_rows.append({"id": r["id"], "protocol": r["protocol"], "truth": truth, "pred": pred})
        keep = _KEEP_TLS if r["protocol"] == "tls" else _KEEP_SSH
        endpoints.append({"id": r["id"], "category": r["category"], "labelled_at": r["labelled_at"],
                          "morrow": _kept(scan, keep), "truth": truth, "pred": pred})
    result = M.score(scored_rows)
    by_cat: Dict[str, int] = {}
    for r in rows:
        by_cat[r["category"]] = by_cat.get(r["category"], 0) + 1
    result.update({
        "generated_at": _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat(),
        "environment": {"python": platform.python_version(), "openssl": ssl.OPENSSL_VERSION,
                        "scanner_version": getattr(sys.modules.get("scanner"), "SCANNER_VERSION", "")},
        "dataset": {"endpoints": len(rows), "by_category": dict(sorted(by_cat.items()))},
        "endpoints": endpoints,
        "retried_after_timeout": retried,
        "rescanned_after_environment_failure": rescanned or [],
        "first_run_at": first_run_at,
    })
    return result


def github_annotations(result: Dict[str, Any], baseline: Optional[Dict[str, Any]], limit: int = 40) -> List[str]:
    """Warnings for the weekly job: every metric that fell below the published baseline, and the
    first `limit` disagreements. Warnings, never errors."""
    out: List[str] = []
    base = (baseline or {}).get("metrics") or {}
    for proto, attrs in result["metrics"].items():
        for attr, m in attrs.items():
            b = ((base.get(proto) or {}).get(attr) or {}).get("f1")
            if b is not None and m.get("f1") is not None and m["f1"] + 0.02 < b:
                out.append(f"::warning title=Accuracy drop::{proto} {attr}: F1 {m['f1']:.3f} < published {b:.3f}")
    for miss in result["misses"][:limit]:
        out.append(f"::warning title=Scanner disagreement::{miss['id']} {miss['attribute']}: "
                   f"label={miss['label']!r} morrow={miss['morrow']!r}")
    if len(result["misses"]) > limit:
        out.append(f"::warning::{len(result['misses']) - limit} more disagreements in the uploaded results")
    return out


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Score Morrow's scanners against the labelled dataset.")
    ap.add_argument("--dataset", default=DATASET)
    ap.add_argument("--only", default="")
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--out", default=os.path.join(RESULTS_DIR, "latest.json"))
    ap.add_argument("--baseline", default=os.path.join(RESULTS_DIR, "published.json"))
    ap.add_argument("--github", action="store_true", help="emit ::warning:: annotations and a step summary")
    ap.add_argument("--drift-from", default="",
                    help="an older labelled dataset: report endpoints whose labels changed since")
    ap.add_argument("--rescan-from", default="",
                    help="a previous results file: keep its scans, rescan only endpoints whose scan "
                         "failed on DNS or routing of the scanning host")
    args = ap.parse_args(argv)

    rows = load_dataset(args.dataset, args.only)
    if args.rescan_from:
        with open(args.rescan_from, encoding="utf-8") as fh:
            result = rescan_environment_failures(rows, json.load(fh))
    else:
        result = run(rows, workers=args.workers)
    if args.drift_from:
        def _all(path: str) -> List[Dict[str, Any]]:
            with open(path, encoding="utf-8") as fh:
                return [json.loads(ln) for ln in fh if ln.strip()]
        result["label_drift"] = M.label_drift(_all(args.drift_from), _all(args.dataset))
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(result, fh, indent=1, sort_keys=True, default=str)
        fh.write("\n")

    table = M.markdown_table(result["metrics"])
    print(table)
    print(f"\n{len(result['misses'])} disagreements; full results in {args.out}")
    if args.github:
        baseline = None
        if os.path.exists(args.baseline):
            with open(args.baseline, encoding="utf-8") as fh:
                baseline = json.load(fh)
        for line in github_annotations(result, baseline):
            print(line)
        for d in (result.get("label_drift") or [])[:40]:
            print(f"::notice title=Endpoint changed since labelled::{d['id']} {d['attribute']}: "
                  f"{d['was']!r} -> {d['now']!r} (relabel accuracy/endpoints.jsonl)")
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a", encoding="utf-8") as fh:
                fh.write("## Scanner accuracy against public endpoints\n\n" + table + "\n\n")
                fh.write(f"{len(result['misses'])} disagreements over {result['dataset']['endpoints']} endpoints.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
