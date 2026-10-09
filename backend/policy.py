# backend/policy.py
from __future__ import annotations

from typing import Any, Dict, List, Optional

# -------------------------
# Helpers
# -------------------------

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

DEFAULT_POLICY: Dict[str, Any] = {
    "min_tls": "1.2",
    "banned_ciphers": ["RC4", "3DES"],
    "allowed_keys": ["ECC", "RSA>=3072"],
    "require_stapling": False,
}

PQC_PROVIDER_CAPABILITY_MATRIX: Dict[str, Dict[str, str]] = {
    "cloudflare": {
        "category": "cdn_edge",
        "hybrid_tls": "provider_feature_check_required",
        "direct_customer_action": "Enable provider-supported post-quantum or hybrid TLS controls for the zone when available, then rescan.",
        "fallback_action": "Keep TLS 1.3 enabled, remove legacy crypto, and track provider rollout status as a migration blocker.",
    },
    "aws": {
        "category": "cloud_edge_or_load_balancer",
        "hybrid_tls": "service_dependent",
        "direct_customer_action": "Check CloudFront, ALB, NLB, and ACM support for hybrid/PQC TLS before claiming readiness.",
        "fallback_action": "Move TLS policy into IaC, enforce TLS 1.3 where supported, and track unsupported services as blockers.",
    },
    "google": {
        "category": "cloud_edge_or_load_balancer",
        "hybrid_tls": "service_dependent",
        "direct_customer_action": "Check Cloud Load Balancing, Cloud CDN, and certificate manager support for hybrid/PQC TLS controls.",
        "fallback_action": "Move TLS policy into IaC, enforce modern TLS, and record provider support as an explicit blocker.",
    },
    "azure": {
        "category": "cloud_edge_or_load_balancer",
        "hybrid_tls": "service_dependent",
        "direct_customer_action": "Check Front Door, Application Gateway, and certificate service support for hybrid/PQC TLS controls.",
        "fallback_action": "Move TLS policy into IaC, enforce modern TLS, and track unsupported services as blockers.",
    },
    "fastly": {
        "category": "cdn_edge",
        "hybrid_tls": "service_dependent",
        "direct_customer_action": "Check Fastly TLS/edge support for hybrid/PQC controls and enable supported settings when available.",
        "fallback_action": "Keep TLS 1.3 enabled, remove weak crypto, manage TLS policy as code, and track Fastly rollout status as a blocker.",
    },
    "akamai": {
        "category": "cdn_edge",
        "hybrid_tls": "service_dependent",
        "direct_customer_action": "Check Akamai edge/TLS product support for hybrid/PQC controls and enable supported settings when available.",
        "fallback_action": "Keep TLS 1.3 enabled, remove weak crypto, manage TLS policy as code, and track Akamai rollout status as a blocker.",
    },
    "customer_tls_terminator": {
        "category": "self_managed_tls",
        "hybrid_tls": "software_stack_dependent",
        "direct_customer_action": "Check Nginx, Envoy, Apache, HAProxy, OpenSSL, BoringSSL, and certificate tooling support.",
        "fallback_action": "Upgrade TLS libraries, standardize config, automate cert rotation, and stage hybrid/PQC in controlled environments.",
    },
    "unknown": {
        "category": "unknown",
        "hybrid_tls": "unknown",
        "direct_customer_action": "Identify where TLS terminates before selecting a PQC migration action.",
        "fallback_action": "Assign an owner and repo, document the unknown provider as a blocker, and investigate DNS/CDN/load-balancer path.",
    },
}

_POLICY_CACHE: Optional[Dict[str, Any]] = None


def load_active_policy() -> Dict[str, Any]:
    global _POLICY_CACHE
    if _POLICY_CACHE is None:
        _POLICY_CACHE = dict(DEFAULT_POLICY)
    return dict(_POLICY_CACHE)


def _sev_rank(sev: str) -> int:
    return SEVERITY_ORDER.get((sev or "").lower(), 0)


def make_finding(
    rule_id: str,
    title: str,
    severity: str,
    remediation: str,
    pqc_mapping: str = "",
    evidence: Optional[Dict[str, Any]] = None,
    confidence: str = "medium",
    confidence_reason: str = "",
) -> Dict[str, Any]:
    return {
        "rule_id": rule_id,
        "severity": (severity or "low").lower(),
        "title": title,
        "fix": remediation,
        "confidence": confidence,
        "confidence_reason": confidence_reason or "",
        "evidence": evidence or {},
        "pqc_note": pqc_mapping or "",
    }


def _get_list(v: Any) -> List[Any]:
    if isinstance(v, list):
        return v
    if v is None:
        return []
    return [v]


def _get_str(v: Any) -> str:
    if v is None:
        return ""
    return str(v)



def _san_dns(f: Dict[str, Any]) -> List[str]:
    return [str(x).lower() for x in _get_list(f.get("san_dns")) if str(x).strip()]


def _ocsp_urls(f: Dict[str, Any]) -> List[str]:
    return [str(x) for x in _get_list(f.get("ocsp_urls")) if str(x).strip()]


def _crl_urls(f: Dict[str, Any]) -> List[str]:
    return [str(x) for x in _get_list(f.get("crl_urls")) if str(x).strip()]



def _ocsp_reachability(f: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [x for x in _get_list(f.get("ocsp_reachability")) if isinstance(x, dict)]


def _crl_reachability(f: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [x for x in _get_list(f.get("crl_reachability")) if isinstance(x, dict)]


def _any_unreachable(entries: List[Dict[str, Any]]) -> bool:
    for e in entries or []:
        try:
            if not bool(e.get("reachable", False)):
                return True
        except Exception:
            continue
    return False


def _ocsp_stapled_status(f: Dict[str, Any]) -> str:
    return str(f.get("ocsp_stapled_status") or "").strip().lower()


def _tls_versions(f: Dict[str, Any]) -> List[str]:
    return [str(x) for x in _get_list(f.get("tls_supported_versions")) if str(x).strip()]


def _weak_tls12(f: Dict[str, Any]) -> List[str]:
    return [str(x) for x in _get_list(f.get("tls12_weak_accepted_ciphers")) if str(x).strip()]


def _key_type(f: Dict[str, Any]) -> str:
    return str(f.get("key_type") or "").upper()


def _key_detail(f: Dict[str, Any]) -> str:
    return str(f.get("key_detail") or "")


# Every public-key algorithm a TLS certificate can carry that a cryptographically relevant quantum
# computer breaks. RSA and ECDSA are the obvious ones; EdDSA (Ed25519/Ed448), X25519/X448, DSA and
# finite-field DH are broken by exactly the same Shor attack and must never be reported as
# quantum-safe or "unknown" just because they are not RSA or EC.
EC_KEY_TYPES = {"EC", "ECC", "ECDSA", "ECDH"}
EDDSA_KEY_TYPES = {"ED25519", "ED448", "X25519", "X448", "EDDSA"}
OTHER_CLASSICAL_KEY_TYPES = {"DSA", "DH", "DHE"}
QUANTUM_VULNERABLE_KEY_TYPES = (
    {"RSA"} | EC_KEY_TYPES | EDDSA_KEY_TYPES | OTHER_CLASSICAL_KEY_TYPES
)


def is_quantum_vulnerable_key_type(key_type: str) -> bool:
    """True when the named public-key algorithm is broken by Shor's algorithm."""
    return str(key_type or "").strip().upper() in QUANTUM_VULNERABLE_KEY_TYPES


def _scan_observed_crypto(f: Dict[str, Any]) -> bool:
    """True when the scan actually retrieved a certificate from the endpoint.

    Rules that assert something about a certificate must not fire when there is no certificate:
    "No CRL distribution points advertised" about a host that refused the connection is a
    fabricated finding, and it is what made a failed scan look like a graded, low-risk asset.
    """
    # scanner._finalise_scan_status is authoritative when it ran: it already decided "ok" means a
    # certificate was parsed. Deciding again from `error` here would disagree with it whenever a
    # late failure (say, chain analysis) set an error after the leaf was read, and the endpoint
    # would then get both SCAN_FAILED and the public-key findings.
    status = str(f.get("scan_status") or "").strip().lower()
    if status:
        return status == "ok"
    # Hand-built fact dicts (tests, imported data) carry no scan_status.
    if str(f.get("error") or "").strip():
        return False
    return bool(f.get("subject") or f.get("key_type") or f.get("not_after"))


def _rsa_key_size(f: Dict[str, Any]) -> int:
    # Modulus size only. An elliptic-curve key's detail is a curve name, and "secp521r1" parsed
    # out to 521 under the digit scan below -- a number that looks like a catastrophically small
    # RSA modulus. Curves are sized on a different scale and are not comparable to RSA>=N policy.
    if _key_type(f) not in {"RSA", "DSA", "DH", "DHE"}:
        return 0
    try:
        bits = int(f.get("key_bits") or 0)
    except (TypeError, ValueError):
        bits = 0
    if bits >= 512:
        return bits
    detail = _key_detail(f)
    digits = "".join(ch if ch.isdigit() else " " for ch in detail).split()
    for part in digits:
        try:
            size = int(part)
        except ValueError:
            continue
        if size >= 512:
            return size
    return 0


def _tls_version_number(version: str) -> float:
    v = str(version or "").strip().lower().replace("tlsv", "").replace("tls", "")
    try:
        return float(v)
    except ValueError:
        return 0.0


def _required_rsa_size(policy: Dict[str, Any]) -> int:
    for item in _get_list(policy.get("allowed_keys")):
        text = str(item or "").strip().upper()
        if text.startswith("RSA>="):
            try:
                return int(text.split(">=", 1)[1])
            except ValueError:
                return 0
    return 0


def _allows_key_type(policy: Dict[str, Any], key_type: str) -> bool:
    allowed = [str(x or "").strip().upper() for x in _get_list(policy.get("allowed_keys"))]
    if not allowed:
        return True
    kt = (key_type or "").strip().upper()
    if kt in ("EC", "ECC", "ECDSA"):
        return any(x in ("EC", "ECC", "ECDSA") for x in allowed)
    if kt == "RSA":
        return any(x == "RSA" or x.startswith("RSA>=") for x in allowed)
    return kt in allowed


def _policy_violation(rule_id: str, severity: str, title: str, evidence: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": rule_id,
        "rule_id": rule_id,
        "severity": severity,
        "title": title,
        "evidence": evidence,
    }


def _host_in_san(host: str, sans: List[str]) -> bool:
    h = (host or "").strip().lower()
    if not h:
        return True
    for s in sans:
        s = (s or "").lower().strip()
        if not s:
            continue
        if s == h:
            return True
        if s.startswith("*."):
            # wildcard matches one label
            suffix = s[1:]  # ".example.com"
            if h.endswith(suffix) and h.count(".") >= suffix.count(".") + 1:
                return True
    return False


def evaluate_policy_violations(facts: Dict[str, Any], policy: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    policy = policy or facts.get("policy") or DEFAULT_POLICY
    violations: List[Dict[str, Any]] = []

    min_tls = _tls_version_number(str(policy.get("min_tls") or ""))
    below_min = [v for v in _tls_versions(facts) if _tls_version_number(v) and _tls_version_number(v) < min_tls]
    if min_tls and below_min:
        violations.append(_policy_violation(
            "POLICY_TLS_BELOW_MIN",
            "high",
            "TLS version below policy minimum",
            {"min_tls": policy.get("min_tls"), "tls_supported_versions": _tls_versions(facts)},
        ))

    banned = [str(x or "").upper() for x in _get_list(policy.get("banned_ciphers"))]
    accepted = [str(x or "") for x in _get_list(facts.get("tls12_accepted_ciphers"))]
    banned_hits = [c for c in accepted for b in banned if b and b in c.upper()]
    if banned_hits:
        violations.append(_policy_violation(
            "POLICY_BANNED_CIPHER",
            "high",
            "Cipher banned by policy is accepted",
            {"banned_ciphers": policy.get("banned_ciphers"), "matched_ciphers": banned_hits},
        ))

    required_rsa = _required_rsa_size(policy)
    actual_rsa = _rsa_key_size(facts)
    if _key_type(facts) == "RSA" and required_rsa and actual_rsa and actual_rsa < required_rsa:
        violations.append(_policy_violation(
            "POLICY_KEY_TOO_SMALL",
            "high",
            "Key too small for policy",
            {"required": f"RSA>={required_rsa}", "actual": _key_detail(facts)},
        ))
    if _key_type(facts) and not _allows_key_type(policy, _key_type(facts)):
        violations.append(_policy_violation(
            "POLICY_KEY_NOT_ALLOWED",
            "high",
            "Key type not allowed by policy",
            {"allowed_keys": policy.get("allowed_keys"), "actual": _key_type(facts)},
        ))
    return violations


def policy_violations_to_findings(facts: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    violations = facts.get("policy_violations")
    if not violations:
        violations = evaluate_policy_violations(facts, facts.get("policy") or load_active_policy())
    for violation in _get_list(violations):
        if not isinstance(violation, dict):
            continue
        rule_id = str(violation.get("rule_id") or "").strip()
        if not rule_id:
            continue
        findings.append(
            make_finding(
                rule_id=rule_id,
                title=str(violation.get("title") or rule_id),
                severity=str(violation.get("severity") or "medium"),
                remediation="Update the endpoint configuration to satisfy the active TLS policy.",
                pqc_mapping="Policy conformance reduces migration risk during crypto-agility work.",
                evidence=violation.get("evidence") if isinstance(violation.get("evidence"), dict) else {},
                confidence="high",
                confidence_reason="Derived from configured policy constraints.",
            )
        )
    return findings


# -------------------------
# Rules
# -------------------------

RULES: List[Dict[str, Any]] = [
    # TLS Protocol
    {
        "id": "NO_TLS13",
        "title": "TLS 1.3 not supported",
        "severity": "high",
        "when": lambda f: ("TLSv1.3" not in _tls_versions(f)) and ("TLSv1.2" in _tls_versions(f)),
        "evidence": lambda f: {"tls_supported_versions": _tls_versions(f)},
        "remediation": "Enable TLS 1.3 on the termination layer (Nginx/Envoy/ALB/IIS) and upgrade crypto libraries.",
        "pqc_mapping": "TLS 1.3 is typically the baseline for hybrid/PQC TLS rollouts.",
        "confidence": "high",
        "confidence_reason": "Derived from active protocol probes.",
    },

    # Weak TLS 1.2
    {
        "id": "WEAK_CIPHER_ACCEPTED",
        "title": "Weak TLS 1.2 ciphers accepted by server",
        "severity": "critical",
        "when": lambda f: len(_weak_tls12(f)) > 0,
        "evidence": lambda f: {"tls12_weak_accepted_ciphers": _weak_tls12(f)[:50]},
        "remediation": "Remove weak suites (RC4/3DES/NULL/EXPORT/MD5). Keep only ECDHE + AES-GCM/CHACHA20.",
        "pqc_mapping": "Baseline hardening should be done before any PQC/hybrid rollout.",
        "confidence": "medium",
        "confidence_reason": "Best-effort probe; depends on client OpenSSL cipher support.",
    },

    # Cert expiry
    {
        "id": "CERT_EXPIRED",
        "title": "Certificate expired",
        "severity": "high",
        "when": lambda f: isinstance(f.get("days_until_expiry"), int) and int(f["days_until_expiry"]) < 0,
        "evidence": lambda f: {"days_until_expiry": f.get("days_until_expiry"), "not_after": f.get("not_after")},
        "remediation": "Renew/rotate certificates immediately. Ensure automated renewal (ACME) if possible.",
        "pqc_mapping": "Rotation discipline matters for PQC rollouts.",
        "confidence": "high",
        "confidence_reason": "Expiry is computed from the presented X.509 certificate.",
    },
    {
        "id": "CERT_EXPIRING_SOON",
        "title": "Certificate expiring soon",
        "severity": "medium",
        "when": lambda f: isinstance(f.get("days_until_expiry"), int) and 0 <= int(f["days_until_expiry"]) <= 30,
        "evidence": lambda f: {"days_until_expiry": f.get("days_until_expiry"), "not_after": f.get("not_after")},
        "remediation": "Schedule certificate renewal/rotation soon; ensure renewal automation.",
        "pqc_mapping": "Rotation discipline matters for PQC rollouts.",
        "confidence": "high",
        "confidence_reason": "Expiry is computed from the presented X.509 certificate.",
    },

    # Hostname vs SAN
    {
        "id": "CERT_HOST_NOT_IN_SAN",
        "title": "Hostname not covered by certificate SAN (possible mismatch)",
        "severity": "high",
        "when": lambda f: bool(f.get("host")) and (len(_san_dns(f)) > 0) and (not _host_in_san(str(f.get("host") or ""), _san_dns(f))),
        "evidence": lambda f: {"host": str(f.get("host") or ""), "san_dns": _san_dns(f)[:50]},
        "remediation": "Ensure the certificate SAN includes the exact hostname (or correct wildcard) used by clients.",
        "pqc_mapping": "Correct identity binding reduces migration incidents during crypto changes.",
        "confidence": "high",
        "confidence_reason": "Derived from SAN entries present in the X.509 certificate.",
    },

    # Chain & verify

    # Verify failure classification
    {
        "id": "VERIFY_HOSTNAME_MISMATCH",
        "title": "Hostname does not match certificate (SAN/CN mismatch)",
        "severity": "high",
        "when": lambda f: str(f.get("verify_reason") or "") == "hostname_mismatch",
        "evidence": lambda f: {
            "verify_error": str(f.get("verify_error") or ""),
            "verify_code": f.get("verify_code"),
            "verify_message": str(f.get("verify_message") or ""),
            "san_dns": _san_dns(f)[:20],
        },
        "remediation": "Issue a certificate that includes the correct DNS name in SAN and ensure the client connects using the expected hostname.",
        "pqc_mapping": "Correct identity binding prevents migration incidents during crypto transitions.",
        "confidence": "high",
        "confidence_reason": "verify_reason is derived from the TLS verification stack's hostname mismatch error.",
    },
    {
        "id": "VERIFY_EXPIRED",
        "title": "Certificate is expired (verification failed)",
        "severity": "high",
        "when": lambda f: str(f.get("verify_reason") or "") == "expired",
        "evidence": lambda f: {
            "verify_error": str(f.get("verify_error") or ""),
            "verify_code": f.get("verify_code"),
            "verify_message": str(f.get("verify_message") or ""),
            "not_after": _get_str(f.get("not_after")),
            "days_until_expiry": int(f.get("days_until_expiry") or 0),
        },
        "remediation": "Renew and deploy a valid certificate. Ensure automated renewal and monitoring are in place.",
        "pqc_mapping": "Operational certificate health is foundational for safe PQC/hybrid rollout waves.",
        "confidence": "high",
        "confidence_reason": "verify_reason is derived from the TLS verification stack's expiry error.",
    },
    {
        "id": "VERIFY_REVOKED",
        "title": "Certificate appears revoked (verification failed)",
        "severity": "critical",
        "when": lambda f: str(f.get("verify_reason") or "") == "revoked",
        "evidence": lambda f: {
            "verify_error": str(f.get("verify_error") or ""),
            "verify_code": f.get("verify_code"),
            "verify_message": str(f.get("verify_message") or ""),
        },
        "remediation": "Replace the certificate immediately. Investigate the revocation cause and validate key handling/incident response.",
        "pqc_mapping": "Revocation hygiene becomes more important during high-volume cert rotations and transitions.",
        "confidence": "high",
        "confidence_reason": "verify_reason is derived from the TLS verification stack's revoked indication.",
    },
    {
        "id": "VERIFY_UNTRUSTED_ISSUER",
        "title": "Certificate chain is untrusted (unknown or self-signed issuer)",
        "severity": "medium",
        "when": lambda f: str(f.get("verify_reason") or "") == "untrusted_issuer",
        "evidence": lambda f: {
            "verify_error": str(f.get("verify_error") or ""),
            "verify_code": f.get("verify_code"),
            "verify_message": str(f.get("verify_message") or ""),
            "issuer": _get_str(f.get("issuer")),
            "chain_source": _get_str(f.get("chain_source")),
        },
        "remediation": "Use a certificate issued by a trusted CA for the target environment, or install the proper trust anchor for internal PKI. Ensure intermediates are served.",
        "pqc_mapping": "Trust consistency reduces surprises when updating crypto primitives and PKI components.",
        "confidence": "high",
        "confidence_reason": "verify_reason is derived from common CA trust failure messages.",
    },
    {
        "id": "VERIFY_MISSING_INTERMEDIATE",
        "title": "Certificate chain may be incomplete (missing intermediate)",
        "severity": "high",
        "when": lambda f: str(f.get("verify_reason") or "") == "missing_intermediate",
        "evidence": lambda f: {
            "verify_error": str(f.get("verify_error") or ""),
            "verify_code": f.get("verify_code"),
            "verify_message": str(f.get("verify_message") or ""),
            "chain_length": int(f.get("chain_length") or 0),
            "chain_issues": _get_list(f.get("chain_issues"))[:10],
        },
        "remediation": "Configure the TLS terminator to serve the complete certificate chain (include the correct intermediate certificates).",
        "pqc_mapping": "Chain correctness is critical for frictionless certificate strategy changes during migrations.",
        "confidence": "high",
        "confidence_reason": "verify_reason is derived from verification errors that commonly indicate missing intermediates.",
    },
    {
        "id": "VERIFY_FAILED",
        "title": "Certificate verification failed for default trust store",
        "severity": "medium",
        "when": lambda f: bool(str(f.get("verify_error") or "").strip()) and str(f.get("verify_reason") or "") in ("", "other", None),
        "evidence": lambda f: {
            "verify_error": str(f.get("verify_error") or ""),
            "verify_code": f.get("verify_code"),
            "verify_message": str(f.get("verify_message") or ""),
        },
        "remediation": "Fix chain/hostname/trust issues. Ensure intermediates are served and SAN matches host.",
        "pqc_mapping": "Clean PKI reduces migration surprises.",
        "confidence": "high",
        "confidence_reason": "Reported directly by the TLS verification stack.",
    },

    {
        "id": "CHAIN_SHORT_OR_UNAVAILABLE",
        "title": "Certificate chain short or unavailable",
        "severity": "medium",
        "when": lambda f: _scan_observed_crypto(f) and int(f.get("chain_length") or 0) <= 1,
        "evidence": lambda f: {"chain_length": int(f.get("chain_length") or 0), "chain_source": str(f.get("chain_source") or "")},
        "remediation": "Ensure the server sends the full chain (include correct intermediates).",
        "pqc_mapping": "Chain issues complicate PQC rollouts.",
        "confidence": "medium",
        "confidence_reason": "Chain analysis is best-effort.",
    },
    {
        "id": "CHAIN_MISSING_INTERMEDIATE",
        "title": "Server likely missing intermediate certificate (incomplete chain)",
        "severity": "high",
        "when": lambda f: bool(str(f.get("verify_error") or "").strip()) and ("unable to get local issuer certificate" in str(f.get("verify_error") or "").lower()),
        "evidence": lambda f: {
            "chain_length": int(f.get("chain_length") or 0),
            "chain_source": str(f.get("chain_source") or ""),
            "verify_error": str(f.get("verify_error") or ""),
        },
        "remediation": "Serve the full certificate chain (leaf + intermediate). Use your CA’s 'fullchain' bundle and configure the TLS terminator to send intermediates.",
        "pqc_mapping": "Incomplete chains break clients and complicate crypto migrations.",
        "confidence": "medium",
        "confidence_reason": "Verification failed for default trust store; chain collected via unverified handshake. Validate with openssl s_client for critical endpoints.",
    },

    # Revocation endpoints
    {
        "id": "CERT_NO_CRL_DP",
        "title": "No CRL distribution points advertised",
        "severity": "low",
        "when": lambda f: _scan_observed_crypto(f) and len(_crl_urls(f)) == 0,
        "evidence": lambda f: {"crl_urls": _crl_urls(f)[:10]},
        "remediation": "Consider adding CRL distribution points to issued certificates if your PKI relies on CRLs.",
        "pqc_mapping": "Revocation hygiene is important during crypto transitions.",
        "confidence": "high",
        "confidence_reason": "CRL Distribution Points are read directly from the X.509 certificate extensions.",
    },
    {
        "id": "CERT_NO_OCSP_AIA",
        "title": "No OCSP responder advertised (AIA)",
        "severity": "low",
        "when": lambda f: _scan_observed_crypto(f) and len(_ocsp_urls(f)) == 0,
        "evidence": lambda f: {"ocsp_urls": _ocsp_urls(f)[:10]},
        "remediation": "Consider including OCSP AIA in issued certificates, and enable OCSP stapling where appropriate.",
        "pqc_mapping": "Revocation posture matters more as certificate strategies evolve for PQC.",
        "confidence": "high",
        "confidence_reason": "AIA OCSP URLs are read directly from the X.509 certificate extensions.",
    },


    {
        "id": "OCSP_ENDPOINT_UNREACHABLE",
        "title": "OCSP responder advertised but unreachable",
        "severity": "medium",
        "when": lambda f: (len(_ocsp_urls(f)) > 0) and (len(_ocsp_reachability(f)) > 0) and _any_unreachable(_ocsp_reachability(f)),
        "evidence": lambda f: {
            "ocsp_urls": _ocsp_urls(f)[:10],
            "ocsp_reachability": _ocsp_reachability(f)[:5],
        },
        "remediation": "Ensure OCSP responder endpoints in AIA are reachable from clients/TLS terminators (DNS, routing, firewalls). If URLs are incorrect, re-issue certificates with correct AIA OCSP URLs.",
        "pqc_mapping": "Revocation reliability matters during cert churn and transition waves (including PQC/hybrid rollouts).",
        "confidence": "medium",
        "confidence_reason": "Reachability is a best-effort HTTP probe; some responders require POST and may not answer HEAD/GET the same way.",
    },
    {
        "id": "CRL_ENDPOINT_UNREACHABLE",
        "title": "CRL distribution point advertised but unreachable",
        "severity": "medium",
        "when": lambda f: (len(_crl_urls(f)) > 0) and (len(_crl_reachability(f)) > 0) and _any_unreachable(_crl_reachability(f)),
        "evidence": lambda f: {
            "crl_urls": _crl_urls(f)[:10],
            "crl_reachability": _crl_reachability(f)[:5],
        },
        "remediation": "Ensure CRL distribution point endpoints are reachable from clients/TLS terminators. If URLs are incorrect, update issuing CA configuration and re-issue certificates.",
        "pqc_mapping": "Revocation hygiene is important during crypto transitions.",
        "confidence": "medium",
        "confidence_reason": "Reachability is a best-effort HTTP probe and may vary by network path.",
    },

    # OCSP stapling (keep it LOW, advisory)
    {
        "id": "OCSP_STAPLING_MISSING",
        "title": "OCSP Stapling Not Enabled",
        "severity": "low",
        # Sprint 9.6: if the client requested OCSP stapling and no stapled response was returned.
        "when": lambda f: bool(f.get("ocsp_stapling_supported", False)) and (not bool(f.get("ocsp_stapled", False))),
        "evidence": lambda f: {
            "ocsp_urls": _ocsp_urls(f)[:10],
            "ocsp_stapled": bool(f.get("ocsp_stapled", False)),
        },
        "remediation": "Enable OCSP stapling on the TLS terminator (e.g., nginx: ssl_stapling on; ssl_stapling_verify on;).",
        "pqc_mapping": "Stapling reduces revocation latency; helpful during cert rotations and PQC transition waves.",
        "confidence": "low",
        "confidence_reason": "Stapling visibility depends on client/TLS stack support; treat as advisory.",
    },


    {
        "id": "OCSP_STATUS_REVOKED",
        "title": "Stapled OCSP indicates certificate is revoked",
        "severity": "critical",
        "when": lambda f: bool(f.get("ocsp_stapled", False)) and (_ocsp_stapled_status(f) == "revoked"),
        "evidence": lambda f: {
            "ocsp_stapled": bool(f.get("ocsp_stapled", False)),
            "ocsp_stapled_status": f.get("ocsp_stapled_status"),
            "ocsp_response_status": f.get("ocsp_response_status"),
            "ocsp_stapled_this_update": f.get("ocsp_stapled_this_update"),
            "ocsp_stapled_next_update": f.get("ocsp_stapled_next_update"),
        },
        "remediation": "Replace the certificate immediately. Investigate CA revocation cause and ensure correct key handling and incident response.",
        "pqc_mapping": "Operational certificate health is foundational for safe crypto transitions.",
        "confidence": "high",
        "confidence_reason": "Status is parsed from the stapled OCSP response (when present).",
    },
    {
        "id": "OCSP_STAPLED_STALE",
        "title": "Stapled OCSP response appears stale/expired",
        "severity": "low",
        "when": lambda f: bool(f.get("ocsp_stapled", False)) and bool(f.get("ocsp_stapled_is_stale", False)),
        "evidence": lambda f: {
            "ocsp_stapled_is_stale": bool(f.get("ocsp_stapled_is_stale", False)),
            "ocsp_stapled_stale_by_days": f.get("ocsp_stapled_stale_by_days"),
            "ocsp_stapled_this_update": f.get("ocsp_stapled_this_update"),
            "ocsp_stapled_next_update": f.get("ocsp_stapled_next_update"),
        },
        "remediation": "Fix OCSP stapling refresh on the TLS terminator and ensure it can reach the OCSP responder. Verify system clock and stapling cache settings.",
        "pqc_mapping": "Stapling reliability helps reduce revocation latency during certificate rotation waves.",
        "confidence": "medium",
        "confidence_reason": "Staleness is derived from the OCSP nextUpdate timestamp, when present.",
    },

    # PQC crypto posture
    {
        "id": "PQC_RSA_ENDPOINT",
        "title": "RSA certificate key detected (quantum-vulnerable class)",
        "severity": "high",
        "when": lambda f: _key_type(f) == "RSA",
        "evidence": lambda f: {"key_type": "RSA", "key_size": _key_detail(f)},
        "remediation": "Inventory RSA usage and plan migration to PQC/hybrid approaches.",
        "pqc_mapping": "RSA -> Kyber (KEM) + Dilithium/Falcon (signatures) in a crypto-agile design.",
        "confidence": "high",
        "confidence_reason": "Public key algorithm extracted from the presented X.509 certificate.",
    },
    {
        "id": "PQC_EC_ENDPOINT",
        "title": "Elliptic-curve public key detected (quantum-vulnerable class)",
        "severity": "medium",
        "when": lambda f: _key_type(f) in EC_KEY_TYPES,
        "evidence": lambda f: {"key_type": _key_type(f), "curve": _key_detail(f), "key_bits": f.get("key_bits")},
        "remediation": "Inventory ECC usage and plan migration to PQC/hybrid approaches.",
        "pqc_mapping": "ECDH/ECDSA -> Kyber (KEM) + Dilithium/Falcon (signatures) in a crypto-agile design.",
        "confidence": "high",
        "confidence_reason": "Public key algorithm extracted from the presented X.509 certificate.",
    },
    {
        # Ed25519 certificates used to fall through every rule here and be reported as an unknown
        # key type -- which downstream reads as "not quantum-vulnerable". EdDSA, X25519/X448, DSA
        # and finite-field DH are all broken by Shor.
        "id": "PQC_CLASSICAL_ENDPOINT",
        "title": "Quantum-vulnerable public key detected (EdDSA/DSA/DH class)",
        "severity": "high",
        "when": lambda f: _key_type(f) in (EDDSA_KEY_TYPES | OTHER_CLASSICAL_KEY_TYPES),
        "evidence": lambda f: {"key_type": _key_type(f), "key_detail": _key_detail(f), "key_bits": f.get("key_bits")},
        "remediation": "Inventory this key's usage and plan migration to PQC/hybrid signatures and key exchange.",
        "pqc_mapping": "EdDSA/DSA -> ML-DSA (FIPS 204); X25519/DH -> ML-KEM (FIPS 203), hybrid X25519MLKEM768 in transition.",
        "confidence": "high",
        "confidence_reason": "Public key algorithm extracted from the presented X.509 certificate.",
    },
    {
        "id": "CRYPTO_NOT_IDENTIFIED",
        "title": "Public key algorithm could not be identified",
        "severity": "medium",
        "when": lambda f: _scan_observed_crypto(f) and _key_type(f) in ("", "UNKNOWN"),
        "evidence": lambda f: {"key_type": f.get("key_type"), "key_detail": _key_detail(f)},
        "remediation": "Inspect the certificate manually; an unclassified key cannot be assumed quantum-safe.",
        "pqc_mapping": "An unclassified public key is an inventory gap, not evidence of PQC readiness.",
        "confidence": "high",
        "confidence_reason": "The certificate parsed but its public key algorithm matched no known class.",
    },
    {
        "id": "SCAN_FAILED",
        "title": "Endpoint could not be scanned",
        "severity": "medium",
        "when": lambda f: not _scan_observed_crypto(f),
        "evidence": lambda f: {
            "scan_status": f.get("scan_status"),
            "error_code": f.get("error_code"),
            "error": str(f.get("error") or "")[:300],
            "host": str(f.get("host") or ""),
            "port": f.get("port"),
        },
        "remediation": "Confirm the host, port and network path, then rescan. No cryptographic posture is known for this endpoint.",
        "pqc_mapping": "An endpoint that was never reached has an unknown quantum posture, not a safe one.",
        "confidence": "high",
        "confidence_reason": "No certificate was retrieved from the endpoint.",
    },
]


# -------------------------
# Core evaluation
# -------------------------

def evaluate_tls_findings(facts: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for rule in RULES:
        try:
            if rule["when"](facts):
                findings.append(
                    make_finding(
                        rule_id=rule["id"],
                        title=rule["title"],
                        severity=rule["severity"],
                        remediation=rule["remediation"],
                        pqc_mapping=rule.get("pqc_mapping", ""),
                        evidence=(rule.get("evidence") or (lambda f: {}))(facts),
                        confidence=rule.get("confidence", "medium"),
                        confidence_reason=rule.get("confidence_reason", ""),
                    )
                )
        except Exception:
            # best-effort rules
            continue

    existing_rule_ids = {str(f.get("rule_id") or "") for f in findings}
    for finding in policy_violations_to_findings(facts):
        if str(finding.get("rule_id") or "") not in existing_rule_ids:
            findings.append(finding)
            existing_rule_ids.add(str(finding.get("rule_id") or ""))

    findings.sort(key=lambda x: _sev_rank(x.get("severity", "")), reverse=True)
    return findings


def risk_level_from_findings(findings: List[Dict[str, Any]]) -> str:
    worst = "low"
    for f in findings:
        sev = (f.get("severity") or "low").lower()
        if _sev_rank(sev) > _sev_rank(worst):
            worst = sev
    return worst


def derive_risk_and_score(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    # Simple scoring: sum severity points, capped.
    points_map = {"critical": 30, "high": 18, "medium": 8, "low": 2, "info": 1}
    score = 0
    for f in findings:
        score += points_map.get((f.get("severity") or "low").lower(), 0)
    score = max(0, min(100, score))

    risk_level = risk_level_from_findings(findings)
    # Keep UI-friendly labels
    risk_label = risk_level

    # Quantum risk level here is a *separate* label: we keep it conservative.
    # "low" is a positive claim about the endpoint's quantum exposure, so it is reserved for scans
    # that actually classified a key. A scan that failed, or one whose key could not be classified,
    # is "unknown" -- never "low".
    rule_ids = {str(f.get("rule_id") or "") for f in findings}
    if "SCAN_FAILED" in rule_ids or "CRYPTO_NOT_IDENTIFIED" in rule_ids:
        q_level = "unknown"
    elif "PQC_RSA_ENDPOINT" in rule_ids or "PQC_CLASSICAL_ENDPOINT" in rule_ids:
        q_level = "high"
    elif "PQC_EC_ENDPOINT" in rule_ids:
        q_level = "medium"
    else:
        q_level = "low"

    return {
        "risk_level": risk_level,
        "risk_label": risk_label,
        "quantum_risk_score": score,
        "quantum_risk_level": q_level,
    }


def derive_pqc_relevance(findings: List[Dict[str, Any]]) -> Dict[str, str]:
    rule_ids = {str(f.get("rule_id") or "") for f in findings}

    # An endpoint that was never reached, or whose key could not be classified, previously came out
    # at pqc_relevance "LOW" with the recommendation text "Unknown key type" -- a contradiction that
    # every count of "low relevance assets" then read as good news. Unknown is its own answer.
    if "SCAN_FAILED" in rule_ids:
        return {
            "pqc_relevance": "UNKNOWN",
            "pqc_recommendation": "Endpoint could not be scanned, so its quantum exposure is unknown. Confirm host/port/network path and rescan.",
        }
    if "CRYPTO_NOT_IDENTIFIED" in rule_ids:
        return {
            "pqc_relevance": "UNKNOWN",
            "pqc_recommendation": "Public key algorithm was not recognised. Inspect the certificate before assuming any quantum posture.",
        }
    if "PQC_RSA_ENDPOINT" in rule_ids:
        return {
            "pqc_relevance": "HIGH",
            "pqc_recommendation": "RSA endpoint detected. Track hybrid TLS readiness and plan a staged migration (crypto-agile).",
        }
    if "PQC_CLASSICAL_ENDPOINT" in rule_ids:
        return {
            "pqc_relevance": "HIGH",
            "pqc_recommendation": "EdDSA/DSA/DH endpoint detected. These are Shor-breakable; plan migration to ML-DSA/ML-KEM.",
        }
    if "PQC_EC_ENDPOINT" in rule_ids:
        return {
            "pqc_relevance": "MEDIUM",
            "pqc_recommendation": "ECC endpoint detected. Maintain crypto-agility and monitor PQC/hybrid TLS deployments.",
        }
    return {
        "pqc_relevance": "LOW",
        "pqc_recommendation": "No classical public-key dependency was identified on this endpoint. Maintain crypto-agility and track PQC readiness.",
    }


def derive_quantum_readiness(facts: Dict[str, Any], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Translate raw TLS facts into a buyer-readable quantum migration assessment.

    This does not claim the endpoint is "quantum proof". It separates what can be
    fixed now from what depends on browser/CDN/load-balancer/CA support.
    """
    supported = set(_tls_versions(facts))
    key_type = _key_type(facts)
    key_detail = _key_detail(facts)
    sig_algorithm = _get_str(facts.get("sig_algorithm"))
    host = _get_str(facts.get("host")).lower()
    issuer = _get_str(facts.get("issuer")).lower()
    finding_ids = {str(f.get("rule_id") or "") for f in findings}

    # Ed25519/Ed448/X25519/X448/DSA/DH are classical public-key dependencies too. Omitting them
    # here reported an Ed25519 endpoint as having no classical dependency at all, which scored it
    # crypto_agility 90 and "ready_to_track_pqc_rollout".
    classical_dependency = is_quantum_vulnerable_key_type(key_type)
    scanned = _scan_observed_crypto(facts)
    tls13_enabled = "TLSv1.3" in supported
    weak_tls = bool(finding_ids.intersection({"WEAK_CIPHER_ACCEPTED", "POLICY_TLS_BELOW_MIN", "POLICY_BANNED_CIPHER"}))
    cert_hygiene_issue = bool(
        finding_ids.intersection(
            {
                "CERT_EXPIRED",
                "CERT_EXPIRING_SOON",
                "VERIFY_EXPIRED",
                "VERIFY_HOSTNAME_MISMATCH",
                "VERIFY_MISSING_INTERMEDIATE",
                "CHAIN_MISSING_INTERMEDIATE",
            }
        )
    )

    provider = "unknown"
    support_status = "unknown"
    support_note = "Provider/CDN/load-balancer was not identified from the certificate or hostname. Confirm where TLS terminates."
    if "cloudflare" in issuer or host.endswith(".pages.dev") or host.endswith(".workers.dev"):
        provider = "cloudflare"
        support_status = "monitor_supported_rollouts"
        support_note = "Likely Cloudflare-fronted. Track Cloudflare PQC/hybrid TLS controls and enable them where available for the zone."
    elif "amazon" in issuer or "aws" in issuer or "cloudfront" in host:
        provider = "aws"
        support_status = "provider_dependent"
        support_note = "Likely AWS-managed TLS. Check ALB/CloudFront/ACM support before claiming PQC-ready TLS."
    elif "google" in issuer or "gts" in issuer or "google" in host:
        provider = "google"
        support_status = "provider_dependent"
        support_note = "Likely Google-managed TLS. Check Cloud Load Balancing/CDN certificate support for PQC/hybrid rollout options."
    elif "fastly" in issuer or "fastly" in host:
        provider = "fastly"
        support_status = "provider_dependent"
        support_note = "Likely Fastly-fronted. Check Fastly edge/TLS support before claiming hybrid/PQC readiness."
    elif "akamai" in issuer or "akamai" in host or "edgesuite" in host or "edgekey" in host:
        provider = "akamai"
        support_status = "provider_dependent"
        support_note = "Likely Akamai-fronted. Check Akamai edge/TLS support before claiming hybrid/PQC readiness."
    elif "microsoft" in issuer or "azure" in host:
        provider = "azure"
        support_status = "provider_dependent"
        support_note = "Likely Azure-managed TLS. Check Front Door/App Gateway/certificate support for PQC/hybrid rollout options."
    elif "let's encrypt" in issuer or "lets encrypt" in issuer:
        provider = "customer_tls_terminator"
        support_status = "software_dependent"
        support_note = "Likely customer-controlled TLS termination. Check Nginx/Envoy/Apache/OpenSSL/BoringSSL support for hybrid/PQC."

    immediate_actions: List[str] = []
    migration_actions: List[str] = []
    blockers: List[str] = []
    controls: List[Dict[str, str]] = []

    if not tls13_enabled:
        immediate_actions.append("Enable TLS 1.3 on the public TLS termination layer.")
        controls.append({"control": "TLS 1.3 baseline", "status": "missing", "why": "Hybrid/PQC TLS rollouts generally assume a modern TLS baseline."})
    else:
        controls.append({"control": "TLS 1.3 baseline", "status": "present", "why": "Modern TLS baseline is present."})

    # "acceptable" on an endpoint that was never reached is an unearned pass: no probe ran, so the
    # absence of a finding is absence of evidence.
    if weak_tls:
        immediate_actions.append("Remove legacy TLS/cipher support before PQC migration.")
        controls.append({"control": "Legacy crypto cleanup", "status": "needed", "why": "Weak classical crypto must be removed before a credible quantum migration."})
    elif not scanned:
        controls.append({"control": "Legacy crypto cleanup", "status": "unknown", "why": "The endpoint could not be scanned, so no cipher evidence was collected."})
    else:
        controls.append({"control": "Legacy crypto cleanup", "status": "acceptable", "why": "No weak TLS/cipher finding was produced by the current probe set."})

    if cert_hygiene_issue:
        immediate_actions.append("Fix certificate validity, hostname, and chain hygiene.")
        controls.append({"control": "Certificate hygiene", "status": "needs_work", "why": "PQC migration fails operationally if basic PKI hygiene is unstable."})
    elif not scanned:
        controls.append({"control": "Certificate hygiene", "status": "unknown", "why": "No certificate was retrieved from this endpoint."})
    else:
        controls.append({"control": "Certificate hygiene", "status": "acceptable", "why": "No major certificate hygiene finding was produced."})

    if classical_dependency:
        migration_actions.append(f"Inventory and migrate {key_type} public-key dependency through a hybrid/PQC-ready certificate/TLS plan.")
        controls.append({"control": "Classical public-key dependency", "status": "present", "why": f"Endpoint presents {key_type} {key_detail or ''}; RSA/ECC/EdDSA/DSA/DH are vulnerable to future cryptographically relevant quantum computers."})
    elif not scanned:
        blockers.append("Endpoint could not be scanned; its public-key algorithm and quantum exposure are unknown.")
        controls.append({"control": "Classical public-key dependency", "status": "unknown", "why": "No certificate was retrieved from this endpoint."})
    else:
        blockers.append("Public-key algorithm could not be classified; inspect TLS terminator and certificate source.")
        controls.append({"control": "Classical public-key dependency", "status": "unknown", "why": "The scan could not classify the endpoint public key."})

    if provider == "unknown":
        blockers.append("TLS provider is unknown, so direct PQC/hybrid enablement cannot be selected automatically.")
    else:
        migration_actions.append(f"Check {provider} support status and enable hybrid/PQC TLS where the provider supports it.")

    migration_actions.extend(
        [
            "Store TLS/certificate policy as infrastructure-as-code so algorithms can be changed safely.",
            "Link this asset to the owning repository and create a validated migration PR.",
            "Rescan after merge and monitor drift so the safer crypto posture is not undone.",
        ]
    )

    # A key that was read off the wire but matched no known algorithm. The scanner recognises every
    # classical algorithm a TLS certificate can carry, so today this can only be an unrecognised --
    # possibly post-quantum -- key. "Possibly" is not evidence. When the scanner learns to name PQC
    # key types, add a positive quantum-safe check here so they stop taking this deduction.
    key_unclassified = scanned and not classical_dependency

    score = 100
    # An unclassified key takes the same deduction as a known-vulnerable one. Otherwise an
    # unreadable certificate scores better than an honestly-identified RSA one, which is the
    # "unknown quietly becomes safe" failure this whole audit is about.
    if classical_dependency or key_unclassified:
        score -= 30
    if not tls13_enabled:
        score -= 20
    if weak_tls:
        score -= 20
    if cert_hygiene_issue:
        score -= 15
    if provider == "unknown":
        score -= 10
    score = max(0, min(100, score))

    if score >= 80:
        readiness = "ready_to_track_pqc_rollout"
    elif score >= 55:
        readiness = "needs_crypto_agility_work"
    else:
        readiness = "migration_blocked_or_high_risk"

    hndl = "high" if classical_dependency else "unknown"
    if not tls13_enabled or weak_tls:
        hndl = "critical" if classical_dependency else "high"

    if not scanned:
        # Nothing was observed. A crypto-agility score of 70 and "needs_crypto_agility_work" were
        # computed entirely from absent evidence: the endpoint lost 20 points for "no TLS 1.3" and
        # 10 for "unknown provider" purely because the scan failed, and kept the other 70 for
        # findings that could not fire. There is no score to publish.
        score = None
        readiness = "not_assessed"
        hndl = "unknown"

    provider_capabilities = dict(PQC_PROVIDER_CAPABILITY_MATRIX.get(provider) or PQC_PROVIDER_CAPABILITY_MATRIX["unknown"])
    migration_plan = [
        {
            "stage": "1_inventory",
            "status": "complete",
            "title": "Inventory public cryptography",
            "description": f"Endpoint scanned. Algorithm={key_type or 'unknown'} {key_detail or ''}; TLS versions={', '.join(sorted(supported)) or 'unknown'}.",
        },
        {
            "stage": "2_classify_data_risk",
            "status": "needs_asset_context",
            "title": "Classify data sensitivity",
            "description": "Set confidentiality_lifetime and criticality. Long-lived sensitive data increases harvest-now/decrypt-later priority.",
        },
        {
            "stage": "3_crypto_agility",
            "status": "ready" if tls13_enabled and not weak_tls and not cert_hygiene_issue else "needs_work",
            "title": "Prepare crypto agility",
            "description": "Remove legacy crypto, enable TLS 1.3, fix certificate hygiene, and make TLS/certificate policy manageable as code.",
        },
        {
            "stage": "4_hybrid_pqc_enablement",
            "status": "provider_check_required" if provider != "unknown" else "blocked_provider_unknown",
            "title": "Enable hybrid/PQC where supported",
            "description": provider_capabilities["direct_customer_action"],
        },
        {
            "stage": "5_validated_code_change",
            "status": "needs_repo_link",
            "title": "Create validated migration PR",
            "description": "Link the endpoint to the owning repo, generate a supported change, validate it in the sandbox, then open a PR.",
        },
        {
            "stage": "6_verified_continuous_control",
            "status": "pending",
            "title": "Verify and monitor drift",
            "description": "Rescan after deployment, store proof, and detect if later changes undo the safer crypto posture.",
        },
    ]

    return {
        "harvest_now_decrypt_later_risk": hndl,
        "classical_crypto_dependency": classical_dependency,
        "classical_algorithm": key_type or "unknown",
        "classical_algorithm_detail": key_detail,
        "signature_algorithm": sig_algorithm,
        "crypto_agility_score": score,
        "quantum_readiness_level": readiness,
        "pqc_migration_status": "blocked_by_provider_or_config" if blockers else "actionable_migration_path",
        "provider_guess": provider,
        "provider_pqc_support_status": support_status,
        "provider_pqc_support_note": support_note,
        "pqc_provider_capabilities": provider_capabilities,
        "pqc_migration_plan": migration_plan,
        "recommended_quantum_safe_controls": controls,
        "immediate_hardening_actions": immediate_actions,
        "pqc_migration_actions": migration_actions,
        "pqc_blockers": blockers,
        "quantum_safe_claim": "not_quantum_proof",
        "quantum_safe_claim_explanation": (
            "This endpoint currently depends on classical public-key cryptography or unverified provider support. "
            "The platform can move it toward quantum-safe readiness, validate supported changes, and track remaining blockers."
        ),
    }


def summarize_results(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(results)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "errors": 0}
    rsa_count = 0
    worst = "low"
    max_score = 0

    for r in results:
        if (r.get("error") or "").strip():
            counts["errors"] += 1

        findings = r.get("findings") or []
        lvl = risk_level_from_findings(findings)
        if _sev_rank(lvl) > _sev_rank(worst):
            worst = lvl

        score = int(r.get("quantum_risk_score") or 0)
        max_score = max(max_score, score)

        for f in findings:
            sev = (f.get("severity") or "").lower()
            if sev in counts:
                counts[sev] += 1
            if f.get("rule_id") == "PQC_RSA_ENDPOINT":
                rsa_count += 1

    # quantum_risk_level: based on max_score (simple)
    if max_score >= 70:
        qlvl = "high"
    elif max_score >= 35:
        qlvl = "medium"
    else:
        qlvl = "low"

    return {
        "total": total,
        "critical": counts["critical"],
        "high": counts["high"],
        "medium": counts["medium"],
        "low": counts["low"],
        "errors": counts["errors"],
        "rsa_count": rsa_count,
        "quantum_risk_score": max_score,
        "quantum_risk_level": qlvl,
    }


# -------------------------
# Backwards-compat exports
# (so you don't break imports when you revert files)
# -------------------------

def evaluate_policies(facts: Dict[str, Any]) -> List[Dict[str, Any]]:
    return evaluate_tls_findings(facts)


def pqc_relevance_and_reco(findings: List[Dict[str, Any]]) -> Dict[str, str]:
    return derive_pqc_relevance(findings)


def risk_level_from_findings_wrapper(findings: List[Dict[str, Any]]) -> str:
    return risk_level_from_findings(findings)


# Keep the exact old names some of your versions imported:
risk_level_from_findings.__name__ = "risk_level_from_findings"
