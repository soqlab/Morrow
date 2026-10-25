from __future__ import annotations

import base64
import hashlib
import json
import math
import statistics
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


_RISK_SCORE = {
    "critical": 90.0,
    "high": 72.0,
    "medium": 45.0,
    "low": 18.0,
    "unknown": 35.0,
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _sha256_text(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _risk_score(value: Any) -> float:
    if isinstance(value, (int, float)):
        return max(0.0, min(100.0, float(value)))
    return _RISK_SCORE.get(str(value or "unknown").lower(), _RISK_SCORE["unknown"])


def _is_truthy(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _looks_like_placeholder_url(value: str) -> bool:
    raw = str(value or "").strip()
    if not raw:
        return True
    try:
        parsed = urlparse(raw)
    except Exception:
        return True
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in {"http", "https"} or not host:
        return True
    if raw.lower() in {"https://legacy.internal", "https://morrow.internal"}:
        return True
    if host in {"example.com", "legacy.example.com", "morrow.example.com"}:
        return True
    if host.endswith(".example.com") or host.endswith(".example"):
        return True
    return False


def autonomous_capability_truth(runtime: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Return machine-readable truth labels so marketing cannot outrun engineering."""
    runtime = runtime or {}
    real_pq_available = bool(runtime.get("real_pq_available"))
    production_ready = bool(runtime.get("production_ready"))
    github_configured = bool(runtime.get("github_configured"))
    cloudflare_configured = bool(runtime.get("cloudflare_configured"))
    postgres_enabled = bool(runtime.get("postgres_enabled"))
    redis_configured = bool(runtime.get("redis_configured"))
    egress_intel_configured = bool(runtime.get("q_intel_live_sources"))
    capabilities = [
        {
            "key": "tls_endpoint_scanning",
            "label": "TLS endpoint scanning",
            "status": "active",
            "truth": "Runs live network scans against submitted endpoints.",
            "customer_boundary": "Only endpoint metadata and TLS/certificate facts are collected.",
        },
        {
            "key": "entropy_binary_hunting",
            "label": "Entropy binary hunting",
            "status": "active",
            "truth": "Runs byte-level constant matching and Shannon entropy analysis on uploaded binaries.",
            "customer_boundary": "Requires customer-submitted binary; no filesystem crawl is performed by default.",
        },
        {
            "key": "ebpf_crypto_sniffer",
            "label": "eBPF crypto sniffer",
            "status": "deployable_package",
            "truth": "Generates bpftrace/systemd/collector artifacts; live telemetry starts only after customer host deployment.",
            "customer_boundary": "Runs inside the customer boundary with approved Linux permissions; payload collection is disabled.",
        },
        {
            "key": "multi_hop_contagion",
            "label": "Multi-hop contagion graph",
            "status": "active_model",
            "truth": "Computes transitive risk propagation from supplied trust graph evidence.",
            "customer_boundary": "No default/sample graph is used for risk claims.",
        },
        {
            "key": "dynamic_qday_countdown",
            "label": "Dynamic Q-Day countdown",
            "status": "active_model" if egress_intel_configured else "internal_feed_model",
            "truth": "Uses the configured Q-Intel feed plus submitted milestones; external live-source ingestion depends on deployment configuration.",
            "customer_boundary": "Consumes public/research metadata, not customer secrets.",
        },
        {
            "key": "multi_variant_pr",
            "label": "Multi-variant PR generation",
            "status": "live_integration" if github_configured else "pr_plan_generator",
            "truth": "Produces PR-ready remediation variants; opening GitHub PRs requires configured GitHub App credentials.",
            "customer_boundary": "Can operate from scan facts and repository metadata without broad source-code export.",
        },
        {
            "key": "canary_traffic_shift",
            "label": "Canary traffic shifting",
            "status": "live_integration" if cloudflare_configured else "artifact_generator",
            "truth": "Generates Cloudflare Worker/Argo/rollback artifacts; no live traffic write happens without provider credentials and approval.",
            "customer_boundary": "Traffic remains at customer/provider edge.",
        },
        {
            "key": "hsm_virtualization",
            "label": "HSM/TPM virtualization",
            "status": "active_model",
            "truth": "Maps supplied HSM/TPM capability evidence to workload needs; collector package exports metadata only.",
            "customer_boundary": "No keys are exported.",
        },
        {
            "key": "hardware_crypto_bridge",
            "label": "HSM/KMS quantum-drift enforcer",
            "status": "active_enforcer",
            "truth": "Evaluates submitted cloud KMS/on-prem HSM observations against key intents and blocks drift when native post-quantum or hardware backing is missing.",
            "customer_boundary": "Provider/HSM collectors run inside customer-controlled accounts and export metadata only.",
        },
        {
            "key": "crypto_anomaly_detection",
            "label": "Crypto-anomaly SIEM/XDR feed",
            "status": "metadata_detector",
            "truth": "Scores packet/TLS metadata for ciphertext harvesting and encrypted-blob movement; SIEM packages are generated for Splunk, Datadog, Sentinel, and Sigma.",
            "customer_boundary": "No packet payloads or plaintext are required.",
        },
        {
            "key": "continuous_compliance_proof",
            "label": "Continuous compliance proof",
            "status": "hash_commitment_attestation",
            "truth": "Produces privacy-preserving hash commitments. It is not a formal ZK-SNARK until a circuit/prover backend is configured.",
            "customer_boundary": "Raw identifiers are excluded from public proof output.",
        },
        {
            "key": "insurance_underwriting_export",
            "label": "Insurance underwriting export",
            "status": "active_export",
            "truth": "Exports aggregate risk/control metrics without raw asset identifiers.",
            "customer_boundary": "Designed for insurer review without exposing domains/IPs by default.",
        },
        {
            "key": "proof_of_agility_underwriting",
            "label": "Cyber-insurance proof-of-agility",
            "status": "signed_proof_api",
            "truth": "Generates signed, privacy-preserving underwriting proof bundles and verifies their signatures.",
            "customer_boundary": "Underwriters receive aggregate proof and hashes, not internal asset lists by default.",
        },
        {
            "key": "hybrid_certificate_generation",
            "label": "Hybrid certificate generation",
            "status": "active" if real_pq_available else "blocked_real_pq_library_missing",
            "truth": "Real post-quantum key generation requires liboqs/python-oqs or pqcrypto. Placeholder post-quantum keys are blocked by API endpoints.",
            "customer_boundary": "Generated key material stays in caller response; production use should be CA/HSM-backed.",
        },
        {
            "key": "production_go_live",
            "label": "Production go-live",
            "status": "go" if production_ready else "blocked",
            "truth": "Go-live requires JWT/SSO, managed Postgres, Redis, signed Airlock, CORS, CSP, observability, and manual exit criteria.",
            "customer_boundary": "Deployment configuration controls this status.",
        },
    ]
    return {
        "generated_at": _now_iso(),
        "kind": "capability_truth_matrix",
        "overall_status": "market_ready" if production_ready else "engineering_ready_not_go_live",
        "infrastructure": {
            "postgres_enabled": postgres_enabled,
            "redis_configured": redis_configured,
            "github_configured": github_configured,
            "cloudflare_configured": cloudflare_configured,
            "real_pq_available": real_pq_available,
            "production_ready": production_ready,
        },
        "capabilities": capabilities,
        "rule": "No endpoint should silently convert missing customer evidence into a production claim.",
    }


def _contains_pq_algorithm(values: Any) -> bool:
    text = " ".join(str(x).lower() for x in (values if isinstance(values, list) else [values]))
    return any(token in text for token in ("ml-kem", "ml_dsa", "ml-dsa", "slh-dsa", "kyber", "dilithium", "x25519mlkem", "pq"))


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def evaluate_hardware_crypto_drift(
    observations: List[Dict[str, Any]],
    key_intents: List[Dict[str, Any]],
    policy: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Detect KMS/HSM drift between intended post-quantum policy and observed hardware roots."""
    observations = observations or []
    key_intents = key_intents or []
    policy = policy or {}
    if not observations or not key_intents:
        raise ValueError("observations and key_intents are required; no provider/HSM defaults are assumed.")

    by_name: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for obs in observations:
        keys = {
            str(obs.get("key_id") or "").strip(),
            str(obs.get("alias") or "").strip(),
            str(obs.get("workload") or "").strip(),
            str(obs.get("name") or "").strip(),
        }
        for key in keys:
            if key:
                by_name[key].append(obs)

    require_native = bool(policy.get("require_native_pq", True))
    allow_software = bool(policy.get("allow_software_fallback", False))
    max_age_hours = _to_float(policy.get("max_observation_age_hours"), 24.0)
    decisions: List[Dict[str, Any]] = []
    blockers = 0
    warnings = 0
    for intent in key_intents:
        intent_id = str(intent.get("key_id") or intent.get("alias") or intent.get("workload") or intent.get("name") or "").strip()
        required_algos = [str(x).lower() for x in (intent.get("required_algorithms") or intent.get("algorithms") or [])]
        require_intent_native = bool(intent.get("require_native_pq", require_native))
        allow_intent_software = bool(intent.get("allow_software_fallback", allow_software))
        candidates = by_name.get(intent_id, []) if intent_id else []
        if not candidates:
            blockers += 1
            decisions.append({
                "intent": intent_id or "unnamed_intent",
                "status": "block",
                "reason": "no_hardware_or_kms_observation",
                "fix": "Run the customer-boundary HSM/KMS bridge collector and submit observations before pushing keys.",
            })
            continue
        best = max(candidates, key=lambda o: int(bool(o.get("hardware_backed"))) + int(bool(o.get("native_pq"))))
        obs_algos = [str(x).lower() for x in (best.get("algorithms") or best.get("supported_algorithms") or [])]
        missing = [algo for algo in required_algos if algo and not any(algo in observed for observed in obs_algos)]
        native_pq = bool(best.get("native_pq") or best.get("native_pq_supported"))
        hardware_backed = bool(best.get("hardware_backed") or best.get("hsm_backed"))
        software_fallback = bool(best.get("software_fallback") or best.get("software_wrapped") or best.get("emulated"))
        age_hours = _to_float(best.get("observation_age_hours"), 0.0)
        reasons: List[str] = []
        status = "pass"
        if missing:
            reasons.append("required_algorithm_missing")
            status = "block"
        if require_intent_native and _contains_pq_algorithm(required_algos) and not native_pq:
            reasons.append("native_pq_not_observed")
            status = "block"
        if not hardware_backed:
            reasons.append("hardware_backing_not_observed")
            status = "block"
        if software_fallback and not allow_intent_software:
            reasons.append("software_fallback_detected")
            status = "block"
        if max_age_hours > 0 and age_hours > max_age_hours:
            reasons.append("stale_observation")
            status = "warn" if status == "pass" else status
        if status == "block":
            blockers += 1
        elif status == "warn":
            warnings += 1
        decisions.append({
            "intent": intent_id or "unnamed_intent",
            "status": status,
            "provider": best.get("provider") or best.get("vendor") or "unknown",
            "region": best.get("region") or "",
            "observed_key_id_hash": _sha256_text(best.get("key_id") or best.get("alias") or intent_id)[:16],
            "required_algorithms": required_algos,
            "observed_algorithms": obs_algos,
            "native_pq": native_pq,
            "hardware_backed": hardware_backed,
            "software_fallback": software_fallback,
            "reasons": reasons or ["policy_satisfied"],
            "fix": "Use a native post-quantum-capable HSM/KMS path or explicitly approve a software fallback exception." if status != "pass" else "",
        })

    return {
        "kind": "hardware_crypto_drift_enforcement",
        "generated_at": _now_iso(),
        "evidence_hash": _sha256_text({"observations": observations, "key_intents": key_intents, "policy": policy}),
        "observation_count": len(observations),
        "intent_count": len(key_intents),
        "ci_gate": "block" if blockers else "warn" if warnings else "pass",
        "blocked_count": blockers,
        "warning_count": warnings,
        "decisions": decisions,
        "truth": "Evaluates submitted customer-boundary KMS/HSM observations; does not hard-code provider post-quantum support.",
    }


def build_crypto_bridge_collector_package(org_id: str, api_base: str = "http://127.0.0.1:8001") -> Dict[str, str]:
    collector = f'''#!/usr/bin/env python3
import json
import os
import shutil
import subprocess
import urllib.request

ORG_ID = os.getenv("MORROW_ORG_ID", "{org_id}")
API_BASE = os.getenv("MORROW_API_BASE", "{api_base}").rstrip("/")


def run(cmd):
    if not shutil.which(cmd[0]):
        return {{"available": False, "command": cmd[0]}}
    try:
        out = subprocess.check_output(cmd, text=True, timeout=30, stderr=subprocess.STDOUT)
        return {{"available": True, "output": out[:12000]}}
    except Exception as exc:
        return {{"available": True, "error": str(exc)}}


def post(payload):
    token = os.getenv("MORROW_API_TOKEN", "").strip()
    headers = {{"Content-Type": "application/json", "x-org-id": ORG_ID, "x-user-role": "operator", "x-user-id": "crypto-bridge"}}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(
        API_BASE + "/v1/hardware/crypto-drift/observations",
        data=json.dumps(payload).encode(),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as response:
        return response.status


def main():
    evidence = {{
        "collector": "hardware_crypto_bridge",
        "org_id": ORG_ID,
        "payload_visible": False,
        "key_exported": False,
        "aws_kms": run(["aws", "kms", "list-keys", "--output", "json"]),
        "gcloud_kms": run(["gcloud", "kms", "keys", "list", "--format=json"]),
        "azure_keyvault": run(["az", "keyvault", "key", "list", "--vault-name", os.getenv("AZURE_KEYVAULT_NAME", "")]),
        "pkcs11": run(["pkcs11-tool", "--list-slots"]),
        "yubihsm": run(["yubihsm-shell", "-a", "list-objects"]),
        "tpm2": run(["tpm2_getcap", "properties-fixed"]),
    }}
    print(json.dumps(evidence, indent=2))
    if os.getenv("MORROW_POST_EVIDENCE", "0") == "1":
        print(json.dumps({{"posted_status": post({{"observations": [evidence]}})}}))


if __name__ == "__main__":
    main()
'''
    readme = """# Hardware Crypto Bridge Collector

Runs inside the customer boundary and collects KMS/HSM capability metadata only.

It does not export keys, secrets, plaintext, ciphertext payloads, or broad filesystem data.
Provider CLI commands run only when the customer has already installed and authenticated them.
Set MORROW_POST_EVIDENCE=1 to post observations back to the platform.
"""
    return {
        "hardware_crypto_bridge_collector.py": collector,
        "README.md": readme,
        "policy.json": json.dumps({
            "org_id": org_id,
            "no_key_export": True,
            "payload_visible": False,
            "requires_customer_provider_credentials": True,
            "generated_at": _now_iso(),
        }, indent=2, sort_keys=True),
    }


def detect_crypto_anomalies(
    records: List[Dict[str, Any]],
    baseline: Optional[Dict[str, Any]] = None,
    policy: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Detect ciphertext harvesting and post-quantum-size anomalies from metadata only."""
    records = records or []
    baseline = baseline or {}
    policy = policy or {}
    if not records:
        raise ValueError("records are required; detector does not synthesize sample traffic.")

    findings: List[Dict[str, Any]] = []
    default_p95 = _to_float(baseline.get("payload_size_p95_bytes"), 4096.0)
    default_out = _to_float(baseline.get("bytes_out_per_minute"), 1_000_000.0)
    for idx, rec in enumerate(records):
        asset = str(rec.get("asset_key") or rec.get("service") or rec.get("source_segment") or f"record-{idx}").strip()
        segment = str(rec.get("segment") or rec.get("source_segment") or "unknown")
        bytes_out = _to_float(rec.get("bytes_out") or rec.get("egress_bytes") or rec.get("bytes_out_per_minute"))
        payload_p95 = _to_float(rec.get("payload_size_p95_bytes") or rec.get("payload_p95_bytes"))
        packet_count = _to_float(rec.get("packet_count") or rec.get("packets"))
        entropy = _to_float(rec.get("entropy") or rec.get("payload_entropy"))
        handshake = _to_float(rec.get("tls_handshake_bytes") or rec.get("handshake_bytes"))
        repeated = _to_float(rec.get("repeated_ciphertext_blocks") or rec.get("ciphertext_block_reuse_count"))
        failed = _to_float(rec.get("failed_handshakes") or rec.get("handshake_failures"))
        baseline_out = _to_float(rec.get("baseline_bytes_out_per_minute"), default_out)
        baseline_p95 = _to_float(rec.get("baseline_payload_size_p95_bytes"), default_p95)
        out_ratio = bytes_out / max(baseline_out, 1.0)
        size_ratio = payload_p95 / max(baseline_p95, 1.0)
        score = 0.0
        reasons: List[str] = []
        if out_ratio >= _to_float(policy.get("egress_spike_ratio"), 4.0):
            score += min(35.0, out_ratio * 6.0)
            reasons.append("egress_volume_spike")
        if size_ratio >= _to_float(policy.get("payload_size_spike_ratio"), 2.5):
            score += min(25.0, size_ratio * 7.0)
            reasons.append("payload_size_shift")
        if entropy >= _to_float(policy.get("high_entropy_threshold"), 7.4) and bytes_out > baseline_out:
            score += 20.0
            reasons.append("high_entropy_egress")
        if repeated >= _to_float(policy.get("ciphertext_reuse_threshold"), 20.0):
            score += 18.0
            reasons.append("repeated_ciphertext_block_pattern")
        if handshake >= _to_float(policy.get("large_handshake_bytes"), 2500.0):
            score += 8.0
            reasons.append("large_handshake_or_hybrid_key_material")
        if failed >= _to_float(policy.get("handshake_failure_threshold"), 25.0):
            score += 8.0
            reasons.append("handshake_failure_spike")
        if not reasons:
            continue
        severity = "critical" if score >= 75 else "high" if score >= 55 else "medium" if score >= 30 else "low"
        findings.append({
            "finding_id": f"canom_{hashlib.sha256(f'{asset}:{idx}:{_canonical(rec)}'.encode()).hexdigest()[:12]}",
            "asset_key": asset,
            "segment": segment,
            "severity": severity,
            "score": round(min(100.0, score), 1),
            "reasons": reasons,
            "metrics": {
                "bytes_out": int(bytes_out),
                "baseline_bytes_out": int(baseline_out),
                "egress_ratio": round(out_ratio, 2),
                "payload_size_p95_bytes": int(payload_p95),
                "payload_size_ratio": round(size_ratio, 2),
                "entropy": round(entropy, 3),
                "packet_count": int(packet_count),
            },
            "hndl_harvesting_signal": any(r in reasons for r in ("egress_volume_spike", "high_entropy_egress", "repeated_ciphertext_block_pattern")),
            "payload_collected": False,
            "recommended_action": "Open SOC investigation, preserve NetFlow/TLS metadata, and validate whether encrypted blobs are being bulk harvested.",
        })
    findings.sort(key=lambda x: (-float(x["score"]), str(x["asset_key"])))
    return {
        "kind": "crypto_anomaly_detection_result",
        "generated_at": _now_iso(),
        "detector_type": "metadata_statistical_anomaly_engine",
        "ai_claim": "Deterministic anomaly scoring is active; external ML/LLM enrichment is optional and not required for this result.",
        "record_count": len(records),
        "finding_count": len(findings),
        "payload_collection": False,
        "findings": findings,
        "summary": {
            "critical": sum(1 for f in findings if f["severity"] == "critical"),
            "high": sum(1 for f in findings if f["severity"] == "high"),
            "hndl_harvesting_signals": sum(1 for f in findings if f["hndl_harvesting_signal"]),
        },
        "evidence_hash": _sha256_text({"records": records, "baseline": baseline, "policy": policy}),
    }


def build_siem_xdr_feed_package(findings: List[Dict[str, Any]], destination: str = "splunk") -> Dict[str, str]:
    findings = findings or []
    destination = str(destination or "splunk").strip().lower()
    events = [
        {
            "time": _now_iso(),
            "source": "pq-crypto-anomaly",
            "sourcetype": "morrow:crypto_anomaly",
            "event": finding,
        }
        for finding in findings
    ]
    splunk = "\n".join(json.dumps(event, sort_keys=True) for event in events) + ("\n" if events else "")
    datadog_monitor = {
        "name": "Post-Quantum Crypto-Anomaly HNDL Harvesting Signal",
        "type": "log alert",
        "query": "logs(\"source:pq-crypto-anomaly @hndl_harvesting_signal:true @score:>55\").index(\"*\").rollup(\"count\").last(\"5m\") > 0",
        "message": "Potential ciphertext harvesting or crypto anomaly detected. Review Morrow finding payload.",
        "tags": ["pq", "crypto-anomaly", "hndl"],
    }
    sentinel_kql = """MORROW_CryptoAnomaly_CL
| where hndl_harvesting_signal_b == true or score_d >= 55
| summarize count(), max(score_d) by asset_key_s, segment_s, severity_s, bin(TimeGenerated, 5m)
| order by max_score_d desc
"""
    sigma = {
        "title": "Post-Quantum Crypto-Anomaly Harvesting Signal",
        "id": f"pq-{uuid.uuid4().hex[:12]}",
        "status": "experimental",
        "description": "Detects metadata-only signals consistent with ciphertext harvesting or abnormal encrypted blob movement.",
        "logsource": {"product": "morrow", "service": "crypto-anomaly"},
        "detection": {
            "selection": {"hndl_harvesting_signal": True},
            "condition": "selection",
        },
        "level": "high",
    }
    readme = f"""# Post-Quantum Crypto-Anomaly SIEM/XDR Package

Destination profile: {destination}

Files:
- splunk-hec-events.ndjson: send to Splunk HEC or index manually.
- datadog-monitor.json: import as a Datadog log monitor.
- microsoft-sentinel-rule.kql: use as an analytic rule query.
- sigma-rule.json: convert through your Sigma pipeline.

Payloads are not included. Events contain metadata-only anomaly findings.
"""
    return {
        "splunk-hec-events.ndjson": splunk,
        "datadog-monitor.json": json.dumps(datadog_monitor, indent=2, sort_keys=True),
        "microsoft-sentinel-rule.kql": sentinel_kql,
        "sigma-rule.json": json.dumps(sigma, indent=2, sort_keys=True),
        "findings.json": json.dumps({"findings": findings, "payload_collection": False}, indent=2, sort_keys=True),
        "README.md": readme,
    }


def _shannon_entropy(chunk: bytes) -> float:
    if not chunk:
        return 0.0
    counts = [0] * 256
    for b in chunk:
        counts[b] += 1
    total = len(chunk)
    entropy = 0.0
    for count in counts:
        if count:
            p = count / total
            entropy -= p * math.log2(p)
    return round(entropy, 4)


_AES_SBOX_PREFIX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
)
_SHA256_K_PREFIX_BE = bytes.fromhex("428a2f9871374491b5c0fbcfe9b5dba5")
_SHA256_K_PREFIX_LE = bytes.fromhex("982f8a4291443771cffbc0b5a5dbb5e9")
_RSA_DER_PREFIXES = (bytes.fromhex("3082010a0282010100"), bytes.fromhex("3082025c020100"))


def entropy_hunt_binary(
    filename: str,
    data: bytes,
    window_size: int = 4096,
    step_size: Optional[int] = None,
) -> Dict[str, Any]:
    """Find stripped, packed, or custom crypto indicators without relying on symbols."""
    window_size = max(256, min(int(window_size or 4096), 65536))
    step = max(128, min(int(step_size or window_size), window_size))
    windows: List[Dict[str, Any]] = []
    for offset in range(0, max(len(data), 1), step):
        chunk = data[offset: offset + window_size]
        if not chunk:
            continue
        entropy = _shannon_entropy(chunk)
        if entropy >= 7.2 or len(data) <= window_size:
            windows.append({
                "offset": offset,
                "size": len(chunk),
                "entropy": entropy,
                "classification": "very_high_entropy" if entropy >= 7.75 else "high_entropy",
            })
        if offset + window_size >= len(data):
            break

    constants: List[Dict[str, Any]] = []
    checks = [
        ("AES_SBOX", _AES_SBOX_PREFIX, "AES substitution-box constant"),
        ("SHA256_K_BE", _SHA256_K_PREFIX_BE, "SHA-256 round constants, big-endian"),
        ("SHA256_K_LE", _SHA256_K_PREFIX_LE, "SHA-256 round constants, little-endian"),
        ("CHACHA20_SIGMA", b"expand 32-byte k", "ChaCha20 sigma constant"),
    ]
    for name, needle, note in checks:
        idx = data.find(needle)
        if idx >= 0:
            constants.append({"name": name, "offset": idx, "note": note})
    for prefix in _RSA_DER_PREFIXES:
        idx = data.find(prefix)
        if idx >= 0:
            constants.append({"name": "RSA_DER_KEY_STRUCTURE", "offset": idx, "note": "ASN.1 DER RSA key structure prefix"})

    printable = sum(1 for b in data if 32 <= b <= 126)
    printable_ratio = round(printable / max(len(data), 1), 4)
    entropies = [w["entropy"] for w in windows]
    high_ratio = round(sum(w["size"] for w in windows) / max(len(data), 1), 4)
    stripped_likelihood = (
        "high" if printable_ratio < 0.08 and high_ratio > 0.35
        else "medium" if printable_ratio < 0.16 and (high_ratio > 0.15 or constants)
        else "low"
    )

    findings: List[Dict[str, Any]] = []
    if constants:
        findings.append({
            "library": "compiled_crypto_constants",
            "risk_level": "high",
            "note": "Binary contains crypto constants even if metadata or symbols are stripped.",
            "count": len(constants),
            "evidence_quality": "probable",
            "detection_basis": "byte-level constant matching",
            "constants": constants,
        })
    if high_ratio > 0.10:
        findings.append({
            "library": "packed_or_obfuscated_binary_region",
            "risk_level": "medium",
            "note": "High-entropy regions may contain packed code, encrypted blobs, or custom crypto tables.",
            "count": len(windows),
            "evidence_quality": "possible_indicator",
            "detection_basis": "Shannon entropy window analysis",
        })

    risk = "high" if constants else ("medium" if high_ratio > 0.10 else "low")
    return {
        "filename": filename,
        "file_size": len(data),
        "window_size": window_size,
        "step_size": step,
        "risk_level": risk,
        "findings": findings,
        "entropy_summary": {
            "mean_high_window_entropy": round(statistics.mean(entropies), 4) if entropies else 0.0,
            "max_window_entropy": round(max(entropies), 4) if entropies else 0.0,
            "high_entropy_window_count": len(windows),
            "high_entropy_byte_ratio": high_ratio,
            "printable_byte_ratio": printable_ratio,
            "stripped_or_packed_likelihood": stripped_likelihood,
            "crypto_constant_hits": len(constants),
        },
        "windows": windows[:200],
        "limits": [
            "Entropy is a risk signal, not proof of exploitable crypto.",
            "Packed binaries, compressed assets, media, and encrypted data can look similar.",
            "Confirm high-risk hits with dynamic tracing, SBOM, or vendor attestation before remediation.",
        ],
    }


def entropy_findings_for_binary(data: bytes) -> List[Dict[str, Any]]:
    return entropy_hunt_binary("binary", data).get("findings", [])


def build_ebpf_crypto_sniffer_package(
    name: str,
    org_id: str,
    api_base: str = "http://127.0.0.1:8001",
) -> Dict[str, str]:
    safe_name = "".join(c if c.isalnum() or c in "-_." else "-" for c in (name or "pq-ebpf-sniffer")).strip("-") or "pq-ebpf-sniffer"
    bpftrace = r'''#!/usr/bin/env bpftrace
/*
  post-quantum passive crypto sniffer - OpenSSL/BoringSSL handshake probes.
  Run with root/CAP_BPF on approved customer hosts only.
  This records metadata only: pid, comm, library function, timestamp. Payloads are never read.
*/
uprobe:/usr/lib*/libssl.so*:SSL_do_handshake,
uprobe:/usr/lib*/libssl.so*:SSL_connect,
uprobe:/usr/lib*/libssl.so*:SSL_accept
{
  @start[tid] = nsecs;
  printf("{\"event\":\"tls_handshake_start\",\"pid\":%d,\"tid\":%d,\"comm\":\"%s\",\"fn\":\"%s\",\"ts_ns\":%llu}\n",
    pid, tid, comm, probe, nsecs);
}

uretprobe:/usr/lib*/libssl.so*:SSL_do_handshake,
uretprobe:/usr/lib*/libssl.so*:SSL_connect,
uretprobe:/usr/lib*/libssl.so*:SSL_accept
/@start[tid]/
{
  printf("{\"event\":\"tls_handshake_done\",\"pid\":%d,\"tid\":%d,\"comm\":\"%s\",\"fn\":\"%s\",\"ret\":%d,\"duration_ns\":%llu,\"ts_ns\":%llu}\n",
    pid, tid, comm, probe, retval, nsecs - @start[tid], nsecs);
  delete(@start[tid]);
}

uprobe:/usr/lib*/libcrypto.so*:EVP_PKEY_keygen,
uprobe:/usr/lib*/libcrypto.so*:EVP_PKEY_derive
{
  printf("{\"event\":\"key_operation\",\"pid\":%d,\"tid\":%d,\"comm\":\"%s\",\"fn\":\"%s\",\"ts_ns\":%llu}\n",
    pid, tid, comm, probe, nsecs);
}
'''
    collector = f'''#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import time
import urllib.request

API_BASE = os.getenv("MORROW_API_BASE", "{api_base}").rstrip("/")
ORG_ID = os.getenv("MORROW_ORG_ID", "{org_id}")
ROLE = os.getenv("MORROW_USER_ROLE", "operator")
USER = os.getenv("MORROW_USER_ID", "pq-ebpf-sniffer")


def post(path, payload):
    headers = {{"Content-Type": "application/json", "x-org-id": ORG_ID, "x-user-role": ROLE, "x-user-id": USER}}
    token = os.getenv("MORROW_API_TOKEN", "").strip()
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(API_BASE + path, data=json.dumps(payload).encode(), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=10) as response:
        return response.status


def normalize(event):
    comm = event.get("comm") or "unknown-process"
    return {{
        "observations": [{{
            "source": "ebpf_crypto_sniffer",
            "asset_key": comm,
            "service_name": comm,
            "peer": "kernel-uprobe",
            "protocol": "tls",
            "tls_version": "TLSv1.3",
            "algorithm": "observed-in-process",
            "cipher": "unknown-passive",
            "metadata": {{
                "pid": event.get("pid"),
                "tid": event.get("tid"),
                "function": event.get("fn"),
                "event": event.get("event"),
                "duration_ns": event.get("duration_ns"),
                "payload_visible": False,
            }},
        }}]
    }}


def main():
    script = os.getenv("MORROW_EBPF_SCRIPT", "pq_crypto_sniffer.bt")
    proc = subprocess.Popen(["bpftrace", script], stdout=subprocess.PIPE, stderr=sys.stderr, text=True)
    assert proc.stdout
    for line in proc.stdout:
        line = line.strip()
        if not line.startswith("{{"):
            continue
        try:
            event = json.loads(line)
            post("/v1/runtime/traffic/import", normalize(event))
            print(json.dumps({{"accepted": True, "event": event.get("event"), "ts": time.time()}}), flush=True)
        except Exception as exc:
            print(json.dumps({{"accepted": False, "error": str(exc), "line": line[:200]}}), flush=True)


if __name__ == "__main__":
    main()
'''
    systemd = f"""[Unit]
Description=post-quantum passive eBPF crypto sniffer
After=network-online.target

[Service]
Type=simple
Environment=MORROW_API_BASE={api_base}
Environment=MORROW_ORG_ID={org_id}
WorkingDirectory=/opt/{safe_name}
ExecStart=/usr/bin/python3 /opt/{safe_name}/collector.py
Restart=always
RestartSec=5
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
"""
    install = f"""#!/usr/bin/env bash
set -euo pipefail
install -d /opt/{safe_name}
cp pq_crypto_sniffer.bt collector.py /opt/{safe_name}/
cp {safe_name}.service /etc/systemd/system/{safe_name}.service
systemctl daemon-reload
systemctl enable --now {safe_name}.service
systemctl status {safe_name}.service --no-pager
"""
    readme = f"""# {safe_name}

Passive eBPF/uProbe crypto discovery package.

What it observes:
- OpenSSL/BoringSSL handshake function calls
- key-operation function calls
- process metadata and timing

What it does not collect:
- packet payloads
- private keys
- request or response bodies
- full memory dumps

Requirements:
- Linux host approved by the customer
- root, CAP_BPF, or equivalent eBPF permission
- `bpftrace` installed
- library paths matching `/usr/lib*/libssl.so*` and `/usr/lib*/libcrypto.so*`

This is passive telemetry. It does not alter traffic or application behavior.
"""
    return {
        "README.md": readme,
        "pq_crypto_sniffer.bt": bpftrace,
        "collector.py": collector,
        f"{safe_name}.service": systemd,
        "install.sh": install,
        "policy.json": json.dumps({
            "name": safe_name,
            "organization_id": org_id,
            "payload_collection": False,
            "requires_customer_host_permission": True,
            "minimum_linux_permissions": ["CAP_BPF or root", "read access to approved crypto library symbols"],
            "generated_at": _now_iso(),
        }, indent=2, sort_keys=True),
    }


def simulate_multi_hop_contagion(
    nodes: List[Dict[str, Any]],
    edges: List[Dict[str, Any]],
    compromised_node_id: str,
    qday_probability: float = 0.35,
    max_depth: int = 6,
) -> Dict[str, Any]:
    by_id = {str(n.get("id") or n.get("node_id") or n.get("name")): dict(n) for n in nodes}
    graph: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for edge in edges:
        src = str(edge.get("from") or edge.get("source") or edge.get("src") or "")
        dst = str(edge.get("to") or edge.get("target") or edge.get("dst") or "")
        if not src or not dst:
            continue
        graph[src].append({
            "to": dst,
            "trust_weight": max(0.0, min(1.0, float(edge.get("trust_weight") or edge.get("weight") or 0.65))),
            "type": str(edge.get("type") or edge.get("relationship") or "trusts"),
        })
    if compromised_node_id not in by_id:
        by_id[compromised_node_id] = {"id": compromised_node_id, "name": compromised_node_id, "risk_level": "critical"}

    qprob = max(0.0, min(1.0, float(qday_probability)))
    max_depth = max(1, min(int(max_depth or 6), 12))
    queue = deque([(compromised_node_id, 0, 100.0, [compromised_node_id])])
    best: Dict[str, Dict[str, Any]] = {}
    while queue:
        node_id, depth, incoming, path = queue.popleft()
        if depth > max_depth:
            continue
        current = best.get(node_id)
        if current and current["contagion_pressure"] >= incoming:
            continue
        node = by_id.get(node_id, {"id": node_id})
        base = _risk_score(node.get("risk_score", node.get("risk_level", "unknown")))
        degraded = min(100.0, base + incoming * qprob)
        best[node_id] = {
            "node_id": node_id,
            "label": node.get("label") or node.get("name") or node_id,
            "depth": depth,
            "base_risk_score": round(base, 2),
            "risk_score_after_contagion": round(degraded, 2),
            "risk_degradation": round(max(0.0, degraded - base), 2),
            "contagion_pressure": round(incoming, 2),
            "path": path,
        }
        if depth == max_depth:
            continue
        for edge in graph.get(node_id, []):
            attenuation = 0.82 ** (depth + 1)
            propagated = incoming * edge["trust_weight"] * attenuation
            if propagated >= 1.0:
                queue.append((edge["to"], depth + 1, propagated, path + [edge["to"]]))

    affected = sorted(best.values(), key=lambda x: (-x["risk_degradation"], x["depth"], x["node_id"]))
    return {
        "origin": compromised_node_id,
        "qday_probability": qprob,
        "affected_count": len(affected),
        "max_depth": max((x["depth"] for x in affected), default=0),
        "affected_nodes": affected,
        "summary": {
            "critical_after": sum(1 for x in affected if x["risk_score_after_contagion"] >= 85),
            "high_after": sum(1 for x in affected if 65 <= x["risk_score_after_contagion"] < 85),
            "largest_degradation": max((x["risk_degradation"] for x in affected), default=0),
        },
    }


def build_dynamic_qday_countdown(model: Dict[str, Any], milestones: List[Dict[str, Any]]) -> Dict[str, Any]:
    estimates = model.get("q_day_50pct_estimates") or {}
    rsa_year = estimates.get("rsa2048") or estimates.get("unknown_classical")
    current_year = datetime.now(timezone.utc).year
    countdown_years = max(0, int(rsa_year) - current_year) if rsa_year else None
    recent = sorted(milestones or [], key=lambda x: str(x.get("date") or ""), reverse=True)[:8]
    pressure = 0.0
    for item in recent:
        sig = str(item.get("significance") or "medium").lower()
        pressure += {"critical": 18, "high": 10, "medium": 5, "low": 2}.get(sig, 4)
        pressure += min(float(item.get("logical_qubits_eq") or 0), 50.0) / 10.0
    pressure = min(100.0, pressure)
    return {
        "qday_50pct_year": rsa_year,
        "countdown_years": countdown_years,
        "research_pressure_score": round(pressure, 1),
        "latest_milestones": recent,
        "curves": model.get("curves", {}),
        "decision": (
            "accelerate_pq_program" if pressure >= 65 or (countdown_years is not None and countdown_years <= 5)
            else "maintain_migration_velocity"
        ),
        "explanation": "Countdown is derived from Q-Intel milestones, logical-qubit estimates, and current break-probability curves.",
    }


def generate_multi_variant_pr(scan_result: Dict[str, Any]) -> Dict[str, Any]:
    host = str(scan_result.get("host") or scan_result.get("asset_key") or "").strip()
    if not host:
        raise ValueError("scan_result.host or scan_result.asset_key is required for PR generation.")
    server = str(scan_result.get("server") or scan_result.get("server_type") or "nginx")
    variants = [
        {
            "id": "A",
            "name": "Max performance - ML-KEM hybrid",
            "algorithm": "X25519MLKEM768",
            "best_for": "latency-sensitive APIs that can run OQS-capable TLS",
            "predicted_latency_delta_ms": "+1 to +4",
            "predicted_handshake_size_delta_kb": "+1.2 to +2.4",
            "risk_reduction": "high",
            "patch": "Set TLS 1.3 only and prefer X25519MLKEM768, then X25519 fallback.",
        },
        {
            "id": "B",
            "name": "Max compatibility - classical hardening plus CAM",
            "algorithm": "TLS1.3 + X25519 fallback + CAM sidecar",
            "best_for": "legacy services where app/library upgrades are risky",
            "predicted_latency_delta_ms": "+0.5 to +2 via local sidecar",
            "predicted_handshake_size_delta_kb": "+0.3 to +1.0",
            "risk_reduction": "medium-high",
            "patch": "Deploy CAM transparent sidecar and keep the application untouched.",
        },
        {
            "id": "C",
            "name": "Maximum cryptographic margin - conservative post-quantum lane",
            "algorithm": "ML-KEM-1024 or Classic McEliece test lane",
            "best_for": "offline, batch, device provisioning, and non-latency-sensitive channels",
            "predicted_latency_delta_ms": "+4 to +25 depending on implementation",
            "predicted_handshake_size_delta_kb": "large; validate MTU and middleboxes",
            "risk_reduction": "very_high",
            "patch": "Create a separate compatibility branch and benchmark before production routing.",
        },
    ]
    pr_body = "\n".join([
        f"# Post-quantum multi-variant remediation for `{host}`",
        "",
        f"Detected server/runtime: `{server}`",
        "",
        "This PR intentionally presents multiple safe paths instead of forcing one migration.",
        "",
        "| Option | Strategy | Algorithm | Best for | Expected impact |",
        "| --- | --- | --- | --- | --- |",
        *[
            f"| {v['id']} | {v['name']} | {v['algorithm']} | {v['best_for']} | {v['predicted_latency_delta_ms']} ms |"
            for v in variants
        ],
        "",
        "## Rollout rule",
        "Start with the lowest-risk branch, route 1% canary traffic, monitor handshake failures and p95 latency, then expand only after evidence passes.",
    ])
    return {
        "asset_key": host,
        "server_type": server,
        "variants": variants,
        "recommended_default": "B" if str(scan_result.get("legacy") or "").lower() in {"1", "true", "yes"} else "A",
        "github_pr_title": f"[post-quantum] Multi-variant remediation options for {host}",
        "github_pr_body": pr_body,
        "benchmark_plan": [
            "Measure handshake success rate by client family.",
            "Compare p50/p95/p99 latency against baseline.",
            "Check packet size, MTU fragmentation, and middlebox compatibility.",
            "Promote only after canary SLOs pass.",
        ],
    }


def build_canary_traffic_shift_package(request: Dict[str, Any]) -> Dict[str, str]:
    service = str(request.get("service_name") or "pq-service")
    baseline = str(request.get("baseline_url") or "").strip()
    candidate = str(request.get("candidate_url") or "").strip()
    invalid = []
    if _looks_like_placeholder_url(baseline):
        invalid.append("baseline_url")
    if _looks_like_placeholder_url(candidate):
        invalid.append("candidate_url")
    if invalid:
        raise ValueError(
            f"{', '.join(invalid)} must be explicit customer/provider HTTP(S) upstreams, not empty/example defaults."
        )
    canary_pct = max(0.1, min(float(request.get("canary_percent") or 1.0), 50.0))
    latency = max(1, int(request.get("latency_p95_ms") or 250))
    failures = max(0.001, min(float(request.get("handshake_failure_rate") or 0.01), 0.50))
    worker = f"""export default {{
  async fetch(request, env) {{
    const pct = Number(env.MORROW_CANARY_PERCENT || "{canary_pct}");
    const rollback = String(env.MORROW_ROLLBACK || "0") === "1";
    const key = request.headers.get("cf-connecting-ip") || crypto.randomUUID();
    const data = new TextEncoder().encode(key);
    const digest = await crypto.subtle.digest("SHA-256", data);
    const score = new Uint8Array(digest)[0] / 255 * 100;
    const target = (!rollback && score < pct) ? "{candidate}" : "{baseline}";
    const upstream = new URL(request.url);
    const selected = new URL(target);
    upstream.protocol = selected.protocol;
    upstream.hostname = selected.hostname;
    upstream.port = selected.port;
    return fetch(upstream.toString(), request);
  }}
}}
"""
    argo = f"""apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata:
  name: {service}
spec:
  strategy:
    canary:
      steps:
        - setWeight: {int(round(canary_pct))}
        - pause: {{duration: 10m}}
        - analysis:
            templates:
              - templateName: pq-handshake-slo
        - setWeight: 25
        - pause: {{duration: 30m}}
"""
    monitor = f"""#!/usr/bin/env python3
import json, os, sys, time, urllib.request
LATENCY_P95_MS = {latency}
FAILURE_RATE = {failures}
METRICS_URL = os.getenv("MORROW_METRICS_URL", "http://localhost:9090/api/v1/query")

def rollback(reason):
    print(json.dumps({{"decision":"rollback","reason":reason,"ts":time.time()}}))
    sys.exit(2)

def main():
    # Wire this to Prometheus/Cloudflare metrics in production.
    p95 = float(os.getenv("MORROW_CANARY_P95_MS", "0") or "0")
    fail = float(os.getenv("MORROW_CANARY_HANDSHAKE_FAILURE_RATE", "0") or "0")
    if p95 and p95 > LATENCY_P95_MS:
        rollback(f"p95 latency {{p95}} > {{LATENCY_P95_MS}}")
    if fail and fail > FAILURE_RATE:
        rollback(f"handshake failure rate {{fail}} > {{FAILURE_RATE}}")
    print(json.dumps({{"decision":"continue","p95_ms":p95,"failure_rate":fail}}))

if __name__ == "__main__":
    main()
"""
    policy = {
        "service_name": service,
        "baseline_url": baseline,
        "candidate_url": candidate,
        "initial_canary_percent": canary_pct,
        "rollback_thresholds": {
            "latency_p95_ms": latency,
            "handshake_failure_rate": failures,
        },
        "automatic_write_actions": False,
        "customer_approval_required_for_enforce": True,
    }
    return {
        "cloudflare-worker.js": worker,
        "argo-rollout.yaml": argo,
        "monitor-and-rollback.py": monitor,
        "canary-policy.json": json.dumps(policy, indent=2, sort_keys=True),
        "README.md": "Deploy the rollout controller only after customer change approval. Monitor metrics before increasing traffic.\n",
    }


def assess_hsm_virtualization(devices: List[Dict[str, Any]], workloads: List[Dict[str, Any]]) -> Dict[str, Any]:
    devices = devices or []
    workloads = workloads or []
    matches: List[Dict[str, Any]] = []
    for workload in workloads:
        required = {str(x).lower() for x in workload.get("required_algorithms") or ["ml-kem", "ml-dsa"]}
        best = None
        best_score = -1.0
        for device in devices:
            algos = {str(x).lower() for x in device.get("algorithms") or []}
            coverage = len(required & algos) / max(len(required), 1)
            tps = float(device.get("tps") or device.get("ops_per_second") or 0)
            need_tps = float(workload.get("tps") or workload.get("ops_per_second") or 1)
            capacity = min(1.0, tps / max(need_tps, 1.0))
            region_bonus = 0.1 if str(device.get("region") or "") == str(workload.get("region") or "") else 0.0
            score = coverage * 70 + capacity * 25 + region_bonus * 5
            if score > best_score:
                best_score = score
                best = device
        matches.append({
            "workload": workload.get("name") or workload.get("id") or "workload",
            "recommended_device": (best or {}).get("name") or (best or {}).get("id") or None,
            "fit_score": round(max(best_score, 0), 1),
            "risk": "low" if best_score >= 80 else "medium" if best_score >= 50 else "high",
            "reason": "hardware-backed post-quantum path available" if best_score >= 80 else "software emulation or capacity planning required",
        })
    return {
        "device_count": len(devices),
        "workload_count": len(workloads),
        "matches": matches,
        "summary": {
            "hardware_ready": sum(1 for m in matches if m["risk"] == "low"),
            "needs_capacity_work": sum(1 for m in matches if m["risk"] == "medium"),
            "software_emulation_risk": sum(1 for m in matches if m["risk"] == "high"),
        },
    }


def build_hsm_collector_package(org_id: str, api_base: str = "http://127.0.0.1:8001") -> Dict[str, str]:
    collector = f'''#!/usr/bin/env python3
import json
import os
import shutil
import subprocess
import urllib.request

ORG_ID = os.getenv("MORROW_ORG_ID", "{org_id}")
API_BASE = os.getenv("MORROW_API_BASE", "{api_base}").rstrip("/")


def run(cmd):
    if not shutil.which(cmd[0]):
        return {{"available": False, "command": cmd[0]}}
    try:
        out = subprocess.check_output(cmd, text=True, timeout=15, stderr=subprocess.STDOUT)
        return {{"available": True, "output": out[:8000]}}
    except Exception as exc:
        return {{"available": True, "error": str(exc)}}


def main():
    evidence = {{
        "org_id": ORG_ID,
        "payload_visible": False,
        "pkcs11": run(["pkcs11-tool", "--list-slots"]),
        "tpm2": run(["tpm2_getcap", "properties-fixed"]),
        "softhsm": run(["softhsm2-util", "--show-slots"]),
    }}
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
'''
    return {
        "hsm_tpm_collector.py": collector,
        "README.md": "Run locally inside the customer boundary. It prints capability metadata only; no keys are exported.\n",
        "policy.json": json.dumps({"org_id": org_id, "no_key_export": True, "payload_visible": False}, indent=2, sort_keys=True),
    }


def generate_continuous_compliance_proof(
    org_id: str,
    assets: List[Dict[str, Any]],
    threshold_pct: float = 98.0,
    approved_algorithms: Optional[List[str]] = None,
) -> Dict[str, Any]:
    approved = [x.lower() for x in (approved_algorithms or ["ml-kem", "ml-dsa", "slh-dsa", "x25519mlkem", "pq", "kyber"])]
    total = len(assets)
    compliant = 0
    for asset in assets:
        material = " ".join(str(asset.get(k) or "") for k in ("algorithm", "key_type", "negotiated_group", "cipher", "tls_group")).lower()
        if any(a in material for a in approved):
            compliant += 1
    pct = round(compliant / total * 100.0, 2) if total else 0.0
    witness = {"total": total, "compliant": compliant, "pct": pct, "threshold": threshold_pct, "org_id": org_id}
    nonce = base64.urlsafe_b64encode(uuid.uuid4().bytes).decode("ascii").rstrip("=")
    commitment = hashlib.sha256((_canonical(witness) + nonce).encode("utf-8")).hexdigest()
    claim = {
        "statement": f"At least {threshold_pct}% of assessed endpoints use approved post-quantum or hybrid algorithms.",
        "result": "pass" if total and pct >= threshold_pct else "fail",
        "public_value": f">={threshold_pct}%" if pct >= threshold_pct else f"<{threshold_pct}%",
        "raw_identifiers_revealed": False,
        "evidence_available": bool(total),
    }
    return {
        "proof_id": f"czk_{uuid.uuid4().hex[:16]}",
        "organization_id": org_id,
        "generated_at": _now_iso(),
        "commitment": commitment,
        "proof_hash": _sha256_text({"claim": claim, "commitment": commitment}),
        "claim": claim,
        "public_signals": {
            "asset_count_bucket": "0" if total == 0 else "1-10" if total <= 10 else "11-100" if total <= 100 else "100+",
            "threshold_pct": threshold_pct,
            "approved_algorithm_families": sorted(set(approved)),
        },
        "private_witness_hash": _sha256_text(witness),
        "verification_note": "Hash-commitment attestation; no IPs, hostnames, domains, vendors, or packet payloads are disclosed.",
    }


def build_underwriting_export(
    org_id: str,
    risk: Dict[str, Any],
    qri_score: float = 0.0,
    controls: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    controls = controls or {}
    risk_reduction = max(0.0, min(35.0, (float(qri_score or 0) / 100.0) * 25.0 + (8.0 if controls.get("cam_enabled") else 0.0) + (2.0 if controls.get("zk_proof") else 0.0)))
    return {
        "api_version": "v1",
        "kind": "pq_insurance_underwriting_export",
        "organization_id": org_id,
        "generated_at": _now_iso(),
        "raw_asset_identifiers_included": False,
        "risk_metrics": {
            "quantum_readiness_index": round(float(qri_score or 0), 1),
            "risk_tier": risk.get("risk_tier", "unknown"),
            "pq_migrated_pct": risk.get("pq_migrated_pct", 0),
            "avg_annual_breach_probability": risk.get("avg_annual_breach_probability", 0),
            "var_99_usd": risk.get("var_99_usd", 0),
            "loaded_premium_annual_usd": risk.get("loaded_premium_annual_usd", 0),
        },
        "verified_controls": {
            "airlock_signed_evidence": bool(controls.get("airlock_signed_evidence")),
            "cam_enabled": bool(controls.get("cam_enabled")),
            "cicd_buzzer": bool(controls.get("cicd_buzzer")),
            "hndl_canaries": int(controls.get("hndl_canaries") or 0),
            "zk_compliance_proof": bool(controls.get("zk_proof")),
            "backup_restore_drill": bool(controls.get("backup_restore_drill")),
        },
        "pricing_signal": {
            "suggested_premium_credit_pct": round(risk_reduction, 1),
            "credit_basis": "QRI score plus verified controls; final pricing belongs to insurer actuarial review.",
        },
        "schema_version": "pq-underwriting-2026-08",
    }


def generate_proof_of_agility(
    org_id: str,
    qri_score: float,
    remediation_metrics: Dict[str, Any],
    controls: Dict[str, Any],
    compliance_proof: Optional[Dict[str, Any]] = None,
    underwriting_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    remediation_metrics = remediation_metrics or {}
    controls = controls or {}
    underwriting_context = underwriting_context or {}
    qri = max(0.0, min(100.0, float(qri_score or 0.0)))
    merged_prs = int(remediation_metrics.get("merged_prs_30d") or remediation_metrics.get("pq_fixes_merged_30d") or 0)
    mttr_days = _to_float(remediation_metrics.get("median_crypto_fix_days"), 30.0)
    drift_closed = int(remediation_metrics.get("drift_events_closed_30d") or 0)
    critical_apps = int(remediation_metrics.get("critical_apps_assessed") or 0)
    total_critical = max(int(remediation_metrics.get("critical_apps_total") or critical_apps or 0), 0)
    coverage = (critical_apps / total_critical * 100.0) if total_critical else 0.0
    control_score = (
        (12.0 if controls.get("airlock_signed_evidence") else 0.0)
        + (10.0 if controls.get("cam_enabled") else 0.0)
        + (8.0 if controls.get("cicd_buzzer") else 0.0)
        + (8.0 if controls.get("hsm_crypto_bridge") else 0.0)
        + (8.0 if controls.get("crypto_anomaly_detection") else 0.0)
        + (6.0 if controls.get("backup_restore_drill") else 0.0)
        + min(8.0, float(controls.get("hndl_canaries") or 0) * 1.5)
    )
    velocity_score = min(20.0, merged_prs * 2.0 + drift_closed * 1.0) + max(0.0, min(10.0, 10.0 - mttr_days / 3.0))
    score = round(min(100.0, qri * 0.45 + coverage * 0.15 + control_score + velocity_score), 1)
    if score >= 85:
        tier = "preferred"
    elif score >= 70:
        tier = "standard_plus"
    elif score >= 50:
        tier = "standard"
    else:
        tier = "manual_review"
    public_claim = {
        "proof_type": "pq_proof_of_agility",
        "score": score,
        "tier": tier,
        "qri_bucket": "80-100" if qri >= 80 else "60-79" if qri >= 60 else "40-59" if qri >= 40 else "0-39",
        "critical_app_coverage_bucket": "80-100" if coverage >= 80 else "50-79" if coverage >= 50 else "0-49",
        "raw_asset_identifiers_revealed": False,
        "raw_vendor_names_revealed": False,
    }
    private_witness = {
        "qri_score": qri,
        "remediation_metrics": remediation_metrics,
        "controls": controls,
        "compliance_proof_hash": _sha256_text(compliance_proof or {}),
        "underwriting_context": underwriting_context,
    }
    return {
        "api_version": "v1",
        "kind": "pq_proof_of_agility",
        "organization_id": org_id,
        "generated_at": _now_iso(),
        "public_claim": public_claim,
        "underwriter_summary": {
            "score": score,
            "tier": tier,
            "suggested_review_path": "straight_through" if tier in {"preferred", "standard_plus"} else "underwriter_review",
            "premium_credit_basis": "Remediation velocity, verified controls, critical-app coverage, and QRI bucket.",
        },
        "privacy": {
            "raw_asset_identifiers_included": False,
            "raw_packet_payloads_included": False,
            "raw_source_code_included": False,
        },
        "private_witness_hash": _sha256_text(private_witness),
        "proof_hash": _sha256_text({"public_claim": public_claim, "private_witness_hash": _sha256_text(private_witness)}),
        "schema_version": "pq-proof-of-agility-2026-08",
    }
