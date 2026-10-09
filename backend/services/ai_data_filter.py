"""Portable customer-side minimization. No networking, filesystem scanning or model calls."""
from __future__ import annotations

import json
import math
import re

ALGORITHMS = frozenset({"RSA", "ECDSA", "ECDH", "ECDHE", "ECC", "DSA", "DH", "AES", "AES-128", "AES-256",
    "AES-256-GCM", "CHACHA20", "CHACHA20-POLY1305", "X25519", "X448", "ED25519", "ED448", "SHA-256", "SHA-384",
    "SHA-512", "ML-KEM", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "ML-DSA", "ML-DSA-44", "ML-DSA-65",
    "ML-DSA-87", "SLH-DSA", "X25519MLKEM768", "UNKNOWN"})
NUMBERS = frozenset({"key_size", "key_bits", "count", "total", "total_assets", "total_findings", "total_scans",
    "critical", "high", "medium", "low", "info", "vulnerable", "quantum_safe", "risk_score", "pqc_ready",
    "compliance_pct", "confidentiality_years", "migration_years", "cnt", "high_risk", "pqc_safe_count", "pqc_unsafe_count", "pqc_readiness_pct"})
CONTAINERS = frozenset({"crypto_metadata", "metadata", "assets", "findings", "components", "hosts", "results",
    "summary", "inventory", "posture", "data", "risk_breakdown", "top_algorithms", "severity_counts", "algorithms", "algorithm_counts"})
ENUMS = {"algorithm": ALGORITHMS, "key_type": ALGORITHMS, "signature_algorithm": ALGORITHMS,
         "tls_version": {"TLSV1", "TLSV1.1", "TLSV1.2", "TLSV1.3", "TLS1.2", "TLS1.3", "UNKNOWN"},
         "severity": {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"},
         "status": {"PASS", "FAIL", "UNKNOWN", "VULNERABLE", "COMPLIANT", "NON-COMPLIANT"}}
SECRET = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:password|passwd|api[_-]?key|access[_-]?token|secret)[\"\']?\s*[:=]|\bBearer\s+\S+|\b(?:sk-[A-Za-z0-9_-]{12,}|AKIA[A-Z0-9]{16})\b|\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", re.I)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def minimize(value, depth=0):
    """Unknown fields AND arbitrary string values are dropped, not merely renamed."""
    if depth > 12:
        return None
    if isinstance(value, list):
        return [item for v in value[:200] if (item := minimize(v, depth + 1)) not in (None, {}, [])]
    if not isinstance(value, dict):
        return value.upper() if isinstance(value, str) and value.upper() in ALGORITHMS else None
    result = {}
    for key, item in value.items():
        if key in NUMBERS and type(item) in (int, float) and math.isfinite(item) and 0 <= item <= 100000000:
            result[key] = item
        elif key in ENUMS and isinstance(item, str) and item.upper() in ENUMS[key]:
            result[key] = item.upper()
        elif key in CONTAINERS:
            clean = minimize(item, depth + 1)
            if clean not in (None, {}, []):
                result[key] = clean
    return result


def filtered_content(value, free_text=False):
    if not isinstance(value, str):
        raise ValueError("Only text or structured cryptographic metadata is supported")
    if len(value) > 64000:
        raise ValueError("AI input exceeds the data boundary limit")
    if free_text:
        if SECRET.search(value):
            raise ValueError("Potential credential detected; request blocked before model dispatch")
        return value
    try:
        data = json.loads(value)
    except (ValueError, TypeError):
        data = {}
    clean = minimize(data)
    return canonical(clean) if clean else "[Text withheld. Only approved structured cryptographic metadata may be analyzed.]"


def sanitize_payload(payload, free_text=False):
    """Provider schemas are built by trusted application code; user content is never a system prompt."""
    result = json.loads(canonical(payload))
    if len(canonical(result)) > 300000:
        raise ValueError("AI request exceeds the data boundary limit")
    messages = result.get("messages", [])
    if not isinstance(messages, list) or len(messages) > 60:
        raise ValueError("Invalid AI conversation")
    for message in messages:
        if message.get("role") == "system":
            continue
        content = message.get("content", "")
        if isinstance(content, str):
            message["content"] = filtered_content(content, free_text)
        elif isinstance(content, list):
            for block in content:
                if block.get("type") == "text":
                    block["text"] = filtered_content(block.get("text", ""), free_text)
                elif block.get("type") == "tool_result":
                    block["content"] = filtered_content(block.get("content", ""), free_text)
                elif block.get("type") in {"thinking", "redacted_thinking", "tool_use"} and message.get("role") == "assistant":
                    # Provider-signed thinking and read-only tool requests belong to this in-memory turn.
                    continue
                else:
                    raise ValueError("Images, files and unknown message blocks are not approved")
        else:
            raise ValueError("Unsupported AI content")
    return result
