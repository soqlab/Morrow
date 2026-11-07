"""Label the accuracy dataset with an independent reference: the OpenSSL and OpenSSH command lines.

This script must never import Morrow code. Its whole value is that the labels it writes come from
a different implementation than the one being measured: `openssl s_client` (OpenSSL 3.5+, the first
release that can offer X25519MLKEM768) for TLS and `ssh -vv` (OpenSSH 9.9+) for SSH. Morrow's TLS
scanner uses Python's ssl module plus its own hand-built ClientHello; its SSH scanner parses
KEXINIT itself. Neither shares a parser with these tools.

What every probe does is an ordinary client handshake, the same thing a browser, `curl` or SSL Labs
does:

  TLS, per endpoint (one connection at a time, at most 7):
    1. a default handshake, to read the certificate the server presents to an ordinary client
    2. one handshake restricted to each of TLS 1.0, 1.1, 1.2 and 1.3
    3. a TLS 1.3 handshake offering only X25519MLKEM768 (then only the other ML-KEM hybrids, if
       the first is refused) -- success means the server supports hybrid post-quantum key exchange
  SSH, per endpoint (one connection):
    a key exchange with no known host keys, so the client stops at "Host key verification failed"
    before any authentication is attempted. The server's KEXINIT proposal is read from -vv output.

Usage (inside a container with OpenSSL 3.5+ and OpenSSH, e.g. alpine:3.22 + `apk add openssl
openssh-client python3`):

    python3 accuracy/reference_probe.py --out accuracy/endpoints.jsonl [--only host,host]

Python 3.11 compatible. Stdlib only.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime as _dt
import json
import os
import re
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
CANDIDATES = os.path.join(HERE, "candidates.txt")
OPTOUT = os.path.join(HERE, "optout.txt")

TIMEOUT = 20            # seconds per handshake
PAUSE = 0.25            # between two connections to the same host
WORKERS = 6             # distinct hosts in flight at once; never two connections to one host

_VERSION_FLAGS = (
    ("TLSv1.0", ["-tls1"]),
    ("TLSv1.1", ["-tls1_1"]),
    ("TLSv1.2", ["-tls1_2"]),
    ("TLSv1.3", ["-tls1_3"]),
)
#: ML-KEM hybrids as OpenSSL names them. X25519MLKEM768 is what browsers ship.
_PQ_PRIMARY = "X25519MLKEM768"
_PQ_SECONDARY = "SecP256r1MLKEM768:SecP384r1MLKEM1024"

_NEW_RE = re.compile(r"^New, (TLSv1(?:\.\d)?|SSLv3|\(NONE\)), Cipher is (\S+)", re.M)
_GROUP_RE = re.compile(r"^Negotiated TLS1\.3 group: (\S+)", re.M)
_TEMP_RE = re.compile(r"^(?:Server|Peer) Temp Key: ([^,\n]+)", re.M)
_PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.S)


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def tool_versions() -> Dict[str, str]:
    out: Dict[str, str] = {}
    for name, cmd in (("openssl", ["openssl", "version"]), ("openssh", ["ssh", "-V"])):
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            out[name] = (p.stdout or p.stderr).strip().splitlines()[0]
        except Exception as exc:  # pragma: no cover - environment dependent
            out[name] = f"unavailable ({exc})"
    return out


def read_candidates(path: str = CANDIDATES) -> List[Dict[str, Any]]:
    optout = set()
    if os.path.exists(OPTOUT):
        with open(OPTOUT, encoding="utf-8") as fh:
            optout = {ln.split("#", 1)[0].strip().lower() for ln in fh if ln.split("#", 1)[0].strip()}
    rows: List[Dict[str, Any]] = []
    seen = set()
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            proto, target = parts[0], parts[1]
            hint = parts[2] if len(parts) > 2 else ""
            host, _, port_s = target.partition(":")
            port = int(port_s) if port_s else (443 if proto == "tls" else 22)
            if host.lower() in optout:
                continue
            key = (proto, host.lower(), port)
            if key in seen:
                continue
            seen.add(key)
            rows.append({"protocol": proto, "host": host, "port": port, "hint": hint})
    return rows


# ── TLS ──────────────────────────────────────────────────────────────────────────────────────

def _s_client(host: str, port: int, extra: List[str]) -> Tuple[str, bool]:
    """Run one s_client handshake. Returns (combined output, tcp_connected)."""
    cmd = ["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host] + extra
    try:
        p = subprocess.run(cmd, input="", capture_output=True, text=True, timeout=TIMEOUT)
        text = (p.stdout or "") + "\n" + (p.stderr or "")
    except subprocess.TimeoutExpired as exc:
        text = ((exc.stdout or b"").decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or ""))
        text += "\n__TIMEOUT__"
    connected = "CONNECTED(" in text
    return text, connected


def _handshake_ok(text: str) -> Optional[str]:
    """The negotiated protocol if the handshake completed, else None."""
    m = _NEW_RE.search(text)
    if not m or m.group(1) == "(NONE)" or m.group(2) == "(NONE)":
        return None
    return m.group(1)


def _failure_reason(text: str) -> str:
    for ln in text.splitlines():
        low = ln.lower()
        if "alert" in low or "error:" in low or "wrong version" in low or "no protocols" in low:
            return ln.strip()[:200]
    if "__TIMEOUT__" in text:
        return "timeout"
    return "no handshake"


def _cert_facts(pem: str) -> Dict[str, Any]:
    p = subprocess.run(["openssl", "x509", "-noout", "-text"], input=pem, capture_output=True, text=True, timeout=60)
    text = p.stdout
    facts: Dict[str, Any] = {}
    m = re.search(r"Signature Algorithm: (\S+)", text)
    facts["sig_algorithm"] = m.group(1) if m else None
    m = re.search(r"Public Key Algorithm: (\S+)", text)
    alg = m.group(1) if m else ""
    facts["public_key_algorithm_raw"] = alg
    facts["cert_key_type"] = {
        "rsaEncryption": "RSA", "rsassaPss": "RSA", "id-ecPublicKey": "EC",
        "ED25519": "Ed25519", "ED448": "Ed448", "dsaEncryption": "DSA",
    }.get(alg, alg or None)
    m = re.search(r"Public-Key: \((\d+) bit\)", text)
    # EdDSA keys print no size; they are fixed by definition.
    facts["cert_key_bits"] = int(m.group(1)) if m else {"ED25519": 256, "ED448": 448}.get(alg)
    m = re.search(r"NIST CURVE: (\S+)", text) or re.search(r"ASN1 OID: (\S+)", text)
    facts["cert_key_curve_raw"] = m.group(1) if m else None
    m = re.search(r"Subject: (.+)", text)
    facts["subject_raw"] = m.group(1).strip() if m else None
    return facts


def probe_tls(host: str, port: int) -> Dict[str, Any]:
    evidence: Dict[str, str] = {}
    labels: Dict[str, Any] = {}

    # 1. Default handshake: the certificate an ordinary client is shown.
    text, connected = _s_client(host, port, ["-showcerts"])
    proto = _handshake_ok(text)
    if not proto:                       # one retry: a lost packet is not a property of the server
        time.sleep(2)
        text, connected = _s_client(host, port, ["-showcerts"])
        proto = _handshake_ok(text)
    if not proto:
        return {"reachable": False, "labels": {}, "evidence": {"default": _failure_reason(text) if connected else "tcp connect failed"}}
    pems = _PEM_RE.findall(text)
    if pems:
        labels.update(_cert_facts(pems[0]))
    evidence["default"] = f"openssl s_client -showcerts: {proto}; leaf {labels.get('public_key_algorithm_raw')} {labels.get('cert_key_bits')} bit, {labels.get('sig_algorithm')}"
    time.sleep(PAUSE)

    # 2. Each protocol version on its own. SECLEVEL=0 for 1.0-1.2 so OpenSSL's own policy does not
    #    refuse an old server the way a 2026 browser would: the question is what the server offers.
    versions: Dict[str, Optional[bool]] = {}
    for label, flags in _VERSION_FLAGS:
        extra = list(flags)
        if label != "TLSv1.3":
            extra += ["-cipher", "ALL:@SECLEVEL=0"]
        t, conn = _s_client(host, port, extra)
        got = _handshake_ok(t)
        if got:
            versions[label] = True
            evidence[label] = f"s_client {' '.join(extra)}: handshake completed ({got})"
        elif conn and "__TIMEOUT__" not in t:
            versions[label] = False
            evidence[label] = f"s_client {' '.join(extra)}: refused ({_failure_reason(t)})"
        else:
            versions[label] = None      # inconclusive: say so rather than guess
            evidence[label] = f"s_client {' '.join(extra)}: inconclusive ({_failure_reason(t)})"
        time.sleep(PAUSE)
    labels["tls_versions"] = versions

    # 3. Hybrid post-quantum key exchange, offered alone.
    pq_groups: List[str] = []
    if versions.get("TLSv1.3"):
        for groups in (_PQ_PRIMARY, _PQ_SECONDARY):
            t, conn = _s_client(host, port, ["-tls1_3", "-groups", groups])
            got = _handshake_ok(t)
            g = _GROUP_RE.search(t)
            if got and g:
                pq_groups.append(g.group(1))
                evidence["pq_hybrid"] = f"s_client -tls1_3 -groups {groups}: negotiated {g.group(1)}"
                break
            evidence["pq_hybrid"] = f"s_client -tls1_3 -groups {groups}: refused ({_failure_reason(t)})"
            time.sleep(PAUSE)
        labels["pq_hybrid"] = bool(pq_groups)
    else:
        labels["pq_hybrid"] = False if versions.get("TLSv1.3") is False else None
        evidence["pq_hybrid"] = "no TLS 1.3, so no ML-KEM hybrid group can be negotiated"
    labels["pq_hybrid_groups"] = pq_groups

    # Derived verdicts. A classical certificate key is Shor-breakable however the session key was
    # agreed; recorded traffic is harvest-now-decrypt-later exposed unless the key exchange that a
    # current (PQ-capable) client gets is a post-quantum hybrid.
    kt = labels.get("cert_key_type")
    labels["cert_quantum_vulnerable"] = kt in ("RSA", "EC", "Ed25519", "Ed448", "DSA") if kt else None
    labels["hndl_vulnerable"] = (not labels["pq_hybrid"]) if labels["pq_hybrid"] is not None else None
    return {"reachable": True, "labels": labels, "evidence": evidence}


# ── SSH ──────────────────────────────────────────────────────────────────────────────────────

_SSH_PQ_TOKENS = ("mlkem", "sntrup", "kyber")


def probe_ssh(host: str, port: int) -> Dict[str, Any]:
    cmd = [
        "ssh", "-vv", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
        "-o", "UserKnownHostsFile=/dev/null", "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", f"ConnectTimeout={TIMEOUT}", "-p", str(port), f"accuracy-probe@{host}", "true",
    ]
    try:
        p = subprocess.run(cmd, input="", capture_output=True, text=True, timeout=TIMEOUT + 5)
        text = (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return {"reachable": False, "labels": {}, "evidence": {"kexinit": "timeout"}}
    lines = text.splitlines()
    try:
        idx = next(i for i, ln in enumerate(lines) if "peer server KEXINIT proposal" in ln)
    except StopIteration:
        return {"reachable": False, "labels": {}, "evidence": {"kexinit": "no server KEXINIT seen"}}

    def _list(prefix: str) -> List[str]:
        for ln in lines[idx:idx + 12]:
            if ln.startswith("debug2: " + prefix + ":"):
                raw = ln.split(":", 2)[2].strip()
                return [x for x in raw.split(",") if x]
        return []

    kex = _list("KEX algorithms")
    hostkeys = _list("host key algorithms")
    ciphers = sorted(set(_list("ciphers ctos")) | set(_list("ciphers stoc")))
    banner = ""
    for ln in lines:
        if "remote software version" in ln:
            banner = ln.split("remote software version", 1)[1].strip()
            break
    pq = [k for k in kex if any(t in k.lower() for t in _SSH_PQ_TOKENS)]
    labels = {
        "kex_algorithms": kex,
        "host_key_algorithms": hostkeys,
        "encryption_algorithms": ciphers,
        "pq_hybrid": bool(pq),
        "pq_hybrid_kex": pq,
        "sha1_kex_offered": any(k in ("diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
                                      "diffie-hellman-group-exchange-sha1") for k in kex),
        # Every SSH host key algorithm deployed today is RSA/ECDSA/EdDSA, so a server with any host
        # key at all is quantum-vulnerable on authentication; HNDL depends on the KEX only.
        "hostkey_quantum_vulnerable": bool(hostkeys),
        "hndl_vulnerable": not pq,
    }
    return {"reachable": True, "labels": labels,
            "evidence": {"kexinit": f"ssh -vv peer server KEXINIT proposal (remote software {banner})"}}


# ── Driver ───────────────────────────────────────────────────────────────────────────────────

def categorise(proto: str, labels: Dict[str, Any]) -> str:
    if proto == "ssh":
        return "ssh_pq_hybrid" if labels.get("pq_hybrid") else "ssh_classical"
    v = labels.get("tls_versions") or {}
    if v.get("TLSv1.0") or v.get("TLSv1.1"):
        return "legacy_tls10_11"
    if v.get("TLSv1.2") and v.get("TLSv1.3") is False:
        return "tls12_only"
    if labels.get("pq_hybrid"):
        return "pq_hybrid"
    return "tls13_classical"


def site_key(host: str) -> str:
    """Same rule as run_accuracy.site_key (kept separate: this script must not import Morrow's
    package). Last two labels, three under a two-letter ccTLD with a short second level."""
    labels = host.lower().rstrip(".").split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and len(labels[-2]) <= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def label_one(row: Dict[str, Any], tools: Dict[str, str]) -> Dict[str, Any]:
    started = _now()
    try:
        res = probe_tls(row["host"], row["port"]) if row["protocol"] == "tls" else probe_ssh(row["host"], row["port"])
    except Exception as exc:  # one bad endpoint must not lose the rest of the run
        res = {"reachable": False, "labels": {}, "evidence": {"error": f"{type(exc).__name__}: {exc}"}}
    rec = {
        "id": f"{row['protocol']}:{row['host']}:{row['port']}",
        "protocol": row["protocol"],
        "host": row["host"],
        "port": row["port"],
        "hint": row["hint"],
        "reachable": res["reachable"],
        "category": categorise(row["protocol"], res["labels"]) if res["reachable"] else "unreachable",
        "labels": res["labels"],
        "evidence": res["evidence"],
        "label_source": tools["openssl"] if row["protocol"] == "tls" else tools["openssh"],
        "labelled_at": started,
    }
    return rec


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--out", default=os.path.join(HERE, "endpoints.jsonl"))
    ap.add_argument("--only", default="", help="comma-separated hosts to (re)label; others are kept from --out")
    ap.add_argument("--workers", type=int, default=WORKERS)
    args = ap.parse_args(argv)

    tools = tool_versions()
    rows = read_candidates()
    keep: Dict[str, Dict[str, Any]] = {}
    if args.only:
        wanted = {h.strip().lower() for h in args.only.split(",") if h.strip()}
        if os.path.exists(args.out):
            with open(args.out, encoding="utf-8") as fh:
                for ln in fh:
                    if ln.strip():
                        r = json.loads(ln)
                        keep[r["id"]] = r
        rows = [r for r in rows if r["host"].lower() in wanted]

    # Records are appended to a .partial file as they complete, so an interrupted run resumes
    # where it stopped instead of probing every host again.
    partial = args.out + ".partial"
    if os.path.exists(partial):
        with open(partial, encoding="utf-8") as fh:
            for ln in fh:
                if ln.strip():
                    r = json.loads(ln)
                    keep[r["id"]] = r
        done_ids = set(keep)
        rows = [r for r in rows if f"{r['protocol']}:{r['host']}:{r['port']}" not in done_ids]

    # Hosts of one site (same registrable domain, e.g. the badssl.com subdomains, which are one
    # server) are labelled one after another by a single worker, never in parallel.
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for r in rows:
        groups.setdefault(site_key(r["host"]), []).append(r)
    lock = threading.Lock()
    done = [0]

    with open(partial, "a", encoding="utf-8", newline="\n") as pfh:
        def label_group(members: List[Dict[str, Any]]) -> None:
            for row in members:
                rec = label_one(row, tools)
                with lock:
                    keep[rec["id"]] = rec
                    pfh.write(json.dumps(rec, sort_keys=True) + "\n")
                    pfh.flush()
                    done[0] += 1
                    print(f"[{done[0]}/{len(rows)}] {rec['id']} -> {rec['category']}", file=sys.stderr, flush=True)

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
            list(pool.map(label_group, sorted(groups.values(), key=len, reverse=True)))

    order = {f"{r['protocol']}:{r['host']}:{r['port']}": i for i, r in enumerate(read_candidates())}
    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        for rec in sorted(keep.values(), key=lambda r: order.get(r["id"], 10**6)):
            fh.write(json.dumps(rec, sort_keys=True) + "\n")
    os.remove(partial)
    print(json.dumps(tools), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
