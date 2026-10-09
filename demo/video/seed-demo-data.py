"""Seed the demo-video database with a fictional customer estate.

Everything here belongs to "Example Financial Group", an invented company.
Every hostname is under example.com or internal.example (reserved example
domains), every certificate issuer is an invented internal CA, and no real
third party is named anywhere.

Scan results are built with the platform's own evaluation pipeline
(policy.evaluate_policies -> derive_risk_and_score -> derive_pqc_relevance ->
derive_quantum_readiness) and then posted through POST /scans/synthetic, so the
stored scans, asset summaries, CBOM, HNDL model and compliance report are
internally consistent with what a real scan of such an estate would produce.

Usage (with demo\\video\\run-demo-server.py already running on 8049):

    backend/.venv/Scripts/python.exe demo/video/seed-demo-data.py
"""
from __future__ import annotations

import json
import os
import pathlib
import random
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

import requests

ROOT = pathlib.Path(__file__).resolve().parents[2]
# PQC_BACKEND_DIR exists because this script is also the quick-start seeder, and in the
# container the backend lives at /app with no repo root above it -- ROOT/"backend" is only
# correct when running from a checkout. The container mounts demo/ and points this at /app.
BACKEND = pathlib.Path(os.environ.get("PQC_BACKEND_DIR") or (ROOT / "backend"))
DEMO_DB = pathlib.Path(os.environ.get("PQC_DEMO_DB") or (ROOT / "demo" / "video" / "demo.db"))
BASE = os.environ.get("PQC_DEMO_BASE", "http://127.0.0.1:8049")
# The account the seeded workspace belongs to. The server creates it at startup from
# PQC_ADMIN_EMAIL / PQC_ADMIN_PASSWORD, so these must match whatever started the server
# (demo/video/run-demo-server.py, or the app service in docker-compose.yml).
EMAIL = os.environ.get("PQC_DEMO_EMAIL") or "avery.chen@example.com"
PASSWORD = os.environ.get("PQC_DEMO_PASSWORD") or "Airlock-Demo-Recording-8049"

COMPANY = "Example Financial Group"

os.environ["PQC_SCANNER_DB"] = str(DEMO_DB)   # before anything imports db
sys.path.insert(0, str(BACKEND))
import policy  # noqa: E402

random.seed(20260923)

NOW = datetime(2026, 9, 23, 9, 0, tzinfo=timezone.utc)

ISSUER_PUBLIC = "CN=Example Public Trust CA G3,O=Example Financial Group,C=GB"
ISSUER_INTERNAL = "CN=Example Internal Issuing CA G2,O=Example Financial Group,C=GB"
ROOT_PUBLIC = "CN=Example Public Trust Root R1,O=Example Financial Group,C=GB"
ROOT_INTERNAL = "CN=Example Internal Root CA,O=Example Financial Group,C=GB"


# ---------------------------------------------------------------- the estate
# key: (algorithm, detail) applied from the first scan onward unless an upgrade
# is listed in `upgrades` as (scan_index, key_type, key_bits, curve).
ESTATE = [
    # host, port, env, team, owner, criticality, lifetime, repo, tags, key, tls, discovered_at_scan
    ("www.example.com", 443, "prod", "digital-channels", "digital-platform", "tier-1", "3y", "edge-gateway", ["internet", "public-web"], ("EC", 256, "secp256r1"), "13", 0),
    ("secure.example.com", 443, "prod", "digital-channels", "digital-platform", "tier-1", "10y+", "edge-gateway", ["internet", "customer-data"], ("RSA", 2048, ""), "13", 0),
    ("payments.example.com", 443, "prod", "payments", "payments-engineering", "tier-1", "10y+", "payments-api", ["internet", "pci", "customer-data"], ("RSA", 2048, ""), "13", 0),
    ("api.example.com", 443, "prod", "payments", "payments-engineering", "tier-1", "10y+", "payments-api", ["internet", "api"], ("EC", 256, "secp256r1"), "13", 0),
    ("openbanking.example.com", 443, "prod", "partner-integration", "open-banking", "tier-1", "10y+", "partner-portal", ["internet", "regulated"], ("EC", 384, "secp384r1"), "13", 0),
    ("mobile-gw.example.com", 443, "prod", "digital-channels", "mobile-engineering", "tier-1", "10y+", "mobile-backend", ["internet", "mobile"], ("EC", 256, "secp256r1"), "13", 0),
    ("auth.example.com", 443, "prod", "core-platform", "identity-platform", "tier-1", "10y+", "edge-gateway", ["internet", "identity"], ("RSA", 3072, ""), "13", 0),
    ("statements.example.com", 443, "prod", "digital-channels", "digital-platform", "tier-1", "10y+", "edge-gateway", ["internet", "customer-data"], ("RSA", 2048, ""), "12", 0),
    ("treasury.example.com", 443, "prod", "payments", "treasury-systems", "tier-1", "10y+", "core-banking-adapter", ["internet", "restricted"], ("RSA", 3072, ""), "13", 0),
    ("cards.example.com", 443, "prod", "payments", "cards-platform", "tier-1", "10y+", "payments-api", ["internet", "pci"], ("EC", 256, "secp256r1"), "13", 0),
    ("fx.example.com", 443, "prod", "payments", "treasury-systems", "tier-2", "5y", "payments-api", ["internet"], ("RSA", 2048, ""), "13", 1),
    ("docs.example.com", 443, "prod", "digital-channels", "digital-platform", "tier-3", "1y", "edge-gateway", ["internet", "public-web"], ("EC", 256, "secp256r1"), "13", 1),
    ("partner.example.com", 443, "prod", "partner-integration", "open-banking", "tier-2", "5y", "partner-portal", ["internet", "partner"], ("RSA", 2048, ""), "13", 1),
    ("payments-hub.internal.example", 443, "prod", "payments", "payments-engineering", "tier-1", "10y+", "core-banking-adapter", ["internal", "east-west", "restricted"], ("RSA", 2048, ""), "12", 0),
    ("ledger.internal.example", 8443, "prod", "core-platform", "core-banking", "tier-1", "10y+", "core-banking-adapter", ["internal", "east-west", "restricted"], ("RSA", 3072, ""), "13", 0),
    ("kyc.internal.example", 443, "prod", "data-platform", "financial-crime", "tier-1", "10y+", "core-banking-adapter", ["internal", "customer-data"], ("EC", 256, "secp256r1"), "13", 1),
    ("reporting.internal.example", 443, "prod", "data-platform", "regulatory-reporting", "tier-2", "10y+", "core-banking-adapter", ["internal", "regulated"], ("RSA", 2048, ""), "12", 1),
    ("ldap.internal.example", 636, "prod", "core-platform", "identity-platform", "tier-1", "10y+", "infra-terraform", ["internal", "identity"], ("RSA", 2048, ""), "12", 2),
    ("mq.internal.example", 5671, "prod", "core-platform", "core-banking", "tier-1", "10y+", "infra-terraform", ["internal", "east-west"], ("RSA", 2048, ""), "12", 2),
    ("vault.internal.example", 8200, "prod", "core-platform", "platform-security", "tier-1", "10y+", "infra-terraform", ["internal", "secrets"], ("EC", 256, "secp256r1"), "13", 2),

    ("staging-www.example.com", 443, "staging", "digital-channels", "digital-platform", "tier-3", "1y", "edge-gateway", ["staging"], ("EC", 256, "secp256r1"), "13", 0),
    ("staging-api.example.com", 443, "staging", "payments", "payments-engineering", "tier-3", "1y", "payments-api", ["staging"], ("EC", 256, "secp256r1"), "13", 0),
    ("staging-payments.example.com", 443, "staging", "payments", "payments-engineering", "tier-3", "1y", "payments-api", ["staging"], ("RSA", 2048, ""), "13", 0),
    ("staging-auth.example.com", 443, "staging", "core-platform", "identity-platform", "tier-3", "1y", "edge-gateway", ["staging"], ("RSA", 2048, ""), "12", 1),
    ("staging-mobile-gw.example.com", 443, "staging", "digital-channels", "mobile-engineering", "tier-3", "1y", "mobile-backend", ["staging"], ("EC", 256, "secp256r1"), "13", 1),
    ("staging-cards.example.com", 443, "staging", "payments", "cards-platform", "tier-3", "1y", "payments-api", ["staging"], ("EC", 256, "secp256r1"), "13", 2),
    ("staging-partner.example.com", 443, "staging", "partner-integration", "open-banking", "tier-3", "1y", "partner-portal", ["staging"], ("RSA", 2048, ""), "12", 2),
    ("staging-ledger.internal.example", 8443, "staging", "core-platform", "core-banking", "tier-3", "1y", "core-banking-adapter", ["staging", "internal"], ("RSA", 2048, ""), "13", 2),
    ("staging-kyc.internal.example", 443, "staging", "data-platform", "financial-crime", "tier-3", "1y", "core-banking-adapter", ["staging", "internal"], ("EC", 256, "secp256r1"), "13", 3),
    ("staging-reporting.internal.example", 443, "staging", "data-platform", "regulatory-reporting", "tier-3", "1y", "core-banking-adapter", ["staging", "internal"], ("RSA", 2048, ""), "12", 3),

    ("dev-api.example.com", 443, "dev", "payments", "payments-engineering", "tier-4", "1y", "payments-api", ["dev"], ("EC", 256, "secp256r1"), "13", 0),
    ("dev-payments.example.com", 443, "dev", "payments", "payments-engineering", "tier-4", "1y", "payments-api", ["dev"], ("RSA", 2048, ""), "12", 1),
    ("dev-auth.example.com", 443, "dev", "core-platform", "identity-platform", "tier-4", "1y", "edge-gateway", ["dev"], ("RSA", 2048, ""), "12", 2),
    ("dev-mobile-gw.example.com", 443, "dev", "digital-channels", "mobile-engineering", "tier-4", "1y", "mobile-backend", ["dev"], ("EC", 256, "secp256r1"), "13", 2),
    ("dev-portal.example.com", 443, "dev", "partner-integration", "open-banking", "tier-4", "1y", "partner-portal", ["dev"], ("RSA", 2048, ""), "12", 3),
    ("sandbox-api.example.com", 443, "dev", "partner-integration", "open-banking", "tier-4", "1y", "partner-portal", ["dev", "sandbox"], ("EC", 256, "secp256r1"), "13", 3),
    ("sandbox-partner.example.com", 443, "dev", "partner-integration", "open-banking", "tier-4", "1y", "partner-portal", ["dev", "sandbox"], ("RSA", 2048, ""), "13", 4),
    ("lab-ledger.internal.example", 8443, "dev", "core-platform", "core-banking", "tier-4", "1y", "core-banking-adapter", ["dev", "internal"], ("RSA", 2048, ""), "12", 4),
]

REPOS = {
    "edge-gateway": "example-financial/edge-gateway",
    "payments-api": "example-financial/payments-api",
    "core-banking-adapter": "example-financial/core-banking-adapter",
    "mobile-backend": "example-financial/mobile-backend",
    "partner-portal": "example-financial/partner-portal",
    "infra-terraform": "example-financial/infra-terraform",
}

# scan_index -> {host: (key_type, key_bits, curve, tls)} posture improvements
UPGRADES = {
    3: {
        "statements.example.com": ("RSA", 2048, "", "13"),
        "dev-auth.example.com": ("RSA", 2048, "", "13"),
    },
    5: {
        "payments-hub.internal.example": ("RSA", 3072, "", "13"),
        "staging-auth.example.com": ("RSA", 2048, "", "13"),
        "dev-payments.example.com": ("RSA", 2048, "", "13"),
    },
    6: {
        "reporting.internal.example": ("RSA", 3072, "", "13"),
        "staging-partner.example.com": ("RSA", 2048, "", "13"),
        "staging-reporting.internal.example": ("RSA", 2048, "", "13"),
        "dev-portal.example.com": ("RSA", 2048, "", "13"),
    },
    7: {
        "secure.example.com": ("EC", 384, "secp384r1", "13"),
        "payments.example.com": ("RSA", 3072, "", "13"),
        "mq.internal.example": ("RSA", 2048, "", "13"),
        "ldap.internal.example": ("RSA", 2048, "", "13"),
    },
}

# The one endpoint already negotiating a hybrid post-quantum key exchange.
HYBRID_HOST = "mobile-gw.example.com"
HYBRID_FROM_SCAN = 6

SCAN_COUNT = 8
SCAN_SPACING_DAYS = 21


def log(msg: str) -> None:
    print(msg, flush=True)


# ---------------------------------------------------------------- fact building
def build_facts(entry, scan_idx: int, scanned_at: datetime):
    host, port, env, team, owner, crit, lifetime, repo, tags, key, tls, first = entry
    key_type, key_bits, curve = key
    tls_pref = tls
    for idx in sorted(UPGRADES):
        if scan_idx >= idx and host in UPGRADES[idx]:
            k_t, k_b, k_c, t_v = UPGRADES[idx][host]
            key_type, key_bits, curve, tls_pref = k_t, k_b, k_c, t_v

    internal = host.endswith("internal.example")
    issuer = ISSUER_INTERNAL if internal else ISSUER_PUBLIC
    tls13 = tls_pref == "13"
    supported = ["TLSv1.2", "TLSv1.3"] if tls13 else ["TLSv1.2"]

    if key_type == "EC":
        key_detail = curve
        sig = "ecdsa-with-SHA384" if key_bits >= 384 else "ecdsa-with-SHA256"
        cipher = "TLS_AES_256_GCM_SHA384" if tls13 else "ECDHE-ECDSA-AES256-GCM-SHA384"
    else:
        key_detail = str(key_bits)
        sig = "sha384WithRSAEncryption" if key_bits >= 3072 else "sha256WithRSAEncryption"
        cipher = "TLS_AES_256_GCM_SHA384" if tls13 else "ECDHE-RSA-AES256-GCM-SHA384"

    # Certificate lifetimes: partner.example.com is deliberately close to expiry
    # in the most recent scans so certificate hygiene has a real example.
    if host == "partner.example.com" and scan_idx >= SCAN_COUNT - 3:
        not_after = scanned_at + timedelta(days=17)
    else:
        not_after = scanned_at + timedelta(days=120 + (hash(host) % 200))
    not_before = not_after - timedelta(days=365)
    days_left = (not_after - scanned_at).days

    weak_ciphers = []
    if not tls13 and scan_idx <= 2 and host in {
        "statements.example.com", "payments-hub.internal.example", "ldap.internal.example"
    }:
        weak_ciphers = ["ECDHE-RSA-AES128-SHA", "AES128-SHA"]

    kx, kx_family, kx_observed = "", "", False
    if tls13:
        if host == HYBRID_HOST and scan_idx >= HYBRID_FROM_SCAN:
            kx, kx_family, kx_observed = "X25519MLKEM768", "pqc_hybrid", True
        else:
            kx, kx_family, kx_observed = ("X25519", "x25519", True) if key_type == "EC" else ("secp256r1", "ec_classical", True)

    facts = {
        "host": host,
        "port": port,
        "error": "",
        "error_code": "",
        "scan_status": "ok",
        "verify_mode": "CERT_REQUIRED",
        "verify_error": "",
        "unverified_fallback": False,
        "tls_version": "TLSv1.3" if tls13 else "TLSv1.2",
        "tls_supported_versions": supported,
        "cipher_name": cipher,
        "cipher_bits": 256,
        "alpn": "h2",
        "key_exchange": kx,
        "key_exchange_family": kx_family,
        "key_exchange_observed": kx_observed,
        "key_exchange_observation_method": "tls_group_extension" if kx_observed else "",
        "subject": f"CN={host},O={COMPANY}",
        "issuer": issuer,
        "not_before": not_before.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "not_after": not_after.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "days_until_expiry": days_left,
        "key_type": key_type,
        "key_detail": key_detail,
        "key_bits": key_bits,
        "key_curve": curve,
        "sig_algorithm": sig,
        "san_dns": [host],
        "key_usage": {"digital_signature": True, "key_encipherment": key_type == "RSA"},
        "eku": ["serverAuth"],
        "basic_constraints": {"ca": False},
        "ocsp_urls": [f"http://ocsp.{'internal.example' if internal else 'example.com'}"],
        "ca_issuers_urls": [f"http://pki.{'internal.example' if internal else 'example.com'}/ca.crt"],
        "crl_urls": [f"http://pki.{'internal.example' if internal else 'example.com'}/crl.pem"],
        "ocsp_stapling_supported": True,
        "ocsp_stapled": not internal,
        # A three-link chain so certificate blast radius and CA contagion have a
        # real PKI to reason about: leaf -> issuing CA -> root.
        "cert_chain": [
            {"subject": f"CN={host},O={COMPANY}", "issuer": issuer,
             "key_type": key_type, "key_bits": key_bits,
             "not_after": not_after.strftime("%Y-%m-%dT%H:%M:%SZ")},
            {"subject": issuer,
             "issuer": ROOT_INTERNAL if internal else ROOT_PUBLIC,
             "key_type": "RSA", "key_bits": 4096,
             "not_after": "2033-01-01T00:00:00Z"},
            {"subject": ROOT_INTERNAL if internal else ROOT_PUBLIC,
             "issuer": ROOT_INTERNAL if internal else ROOT_PUBLIC,
             "key_type": "RSA", "key_bits": 4096,
             "not_after": "2039-01-01T00:00:00Z"},
        ],
        "chain_length": 3,
        "chain_issues": [],
        "chain_source": "handshake",
        "chain_confidence": "high",
        "tls12_accepted_ciphers": ["ECDHE-RSA-AES256-GCM-SHA384"] + weak_ciphers,
        "tls12_weak_accepted_ciphers": weak_ciphers,
        "forward_secrecy_possible": True,
    }

    findings = policy.evaluate_policies(facts)
    facts["findings"] = findings
    facts.update(policy.derive_risk_and_score(findings))
    facts.update(policy.derive_pqc_relevance(findings))
    facts.update(policy.derive_quantum_readiness(facts, findings))
    return facts


# ---------------------------------------------------------------- http helpers
class Api:
    def __init__(self):
        self.s = requests.Session()
        r = self.s.post(f"{BASE}/auth/login", json={"email": EMAIL, "password": PASSWORD}, timeout=30)
        r.raise_for_status()
        data = r.json()
        self.token = data["access_token"]
        self.user = data["user"]
        self.s.headers.update({"Authorization": f"Bearer {self.token}"})

    def post(self, path, body=None, ok=(200, 201)):
        r = self.s.post(f"{BASE}{path}", json=body, timeout=180)
        if r.status_code not in ok:
            log(f"  ! POST {path} -> {r.status_code} {r.text[:200]}")
        return r

    def put(self, path, body=None):
        r = self.s.put(f"{BASE}{path}", json=body, timeout=60)
        if r.status_code >= 300:
            log(f"  ! PUT {path} -> {r.status_code} {r.text[:200]}")
        return r

    def get(self, path):
        return self.s.get(f"{BASE}{path}", timeout=120)


# ---------------------------------------------------------------- direct rows
def brand_tenant(org_id: str) -> None:
    """Name the workspace after the fictional company and give the signed-in
    operator a human name. There is no API for either, and both are cosmetic."""
    conn = sqlite3.connect(str(DEMO_DB), timeout=30)
    try:
        conn.execute("UPDATE organizations SET name=? WHERE id=?", (COMPANY, org_id))
        conn.execute("UPDATE pqc_users SET full_name=?, org_id=? WHERE email=?",
                     ("Avery Chen", org_id, EMAIL))
        conn.commit()
    finally:
        conn.close()


def main() -> None:
    default_org = "00000000-0000-0000-0000-000000000001"
    brand_tenant(default_org)

    api = Api()
    org_id = api.user.get("org_id")
    log(f"signed in; workspace={org_id}")

    # ---------------------------------------------------------- repositories
    import db as dbmod  # imported late: PQC_SCANNER_DB is already set above
    dbmod.set_current_organization_id(org_id)
    repo_ids = {}
    for slug, name in REPOS.items():
        row = dbmod.upsert_repository(name, f"https://github.com/{name}")
        repo_ids[slug] = int(row.get("id") or 0)
    log(f"repositories: {len(repo_ids)}")

    # ---------------------------------------------------------- scan history
    scan_ids = []
    for i in range(SCAN_COUNT):
        scanned_at = NOW - timedelta(days=SCAN_SPACING_DAYS * (SCAN_COUNT - 1 - i), hours=random.randint(0, 6))
        targets = [e for e in ESTATE if e[11] <= min(i, 4)]
        results = [build_facts(e, i, scanned_at) for e in targets]
        scan_id = f"scan-{scanned_at.strftime('%Y%m%d')}-estate"
        r = api.post("/scans/synthetic", {
            "scan_id": scan_id,
            "created_at": scanned_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "results": results,
            "auto_close_merged": False,
        })
        if r.status_code == 200:
            scan_ids.append(scan_id)
            log(f"scan {i + 1}/{SCAN_COUNT} {scanned_at.date()} -> {len(results)} endpoints")

    # ---------------------------------------------------------- asset context
    for entry in ESTATE:
        host, port, env, team, owner, crit, lifetime, repo, tags, key, tls, first = entry
        api.put(f"/assets/{host}:{port}", {
            "owner": owner,
            "team": team,
            "environment": env,
            "criticality": crit,
            "confidentiality_lifetime": lifetime,
            "tags": tags,
            "notes": f"{COMPANY} demo estate record (fictional).",
            "metadata": {"business_service": team, "data_classification":
                         "restricted" if "restricted" in tags or "customer-data" in tags else "internal"},
            "repository_id": repo_ids.get(repo, 0),
        })
    log(f"assets: {len(ESTATE)} with owner, team, environment, criticality and data lifetime")

    # ---------------------------------------------------------- collections
    for name, tag in [("Internet-facing production", "internet"),
                      ("Internal east-west", "internal"),
                      ("PCI scope", "pci")]:
        api.post("/collections", {
            "name": name,
            "description": f"{COMPANY} demo estate",
            "targets_text": "\n".join(f"{e[0]}:{e[1]}" for e in ESTATE if tag in e[8]),
        })

    # ---------------------------------------------------------- remediations
    remediation_plan = [
        ("statements.example.com:443", "edge-gateway", "infra/edge/statements-tls.tf",
         "TLS 1.2-only endpoint carrying 10-year customer statement data",
         "Enable TLS 1.3 and remove the legacy cipher list before hybrid key exchange can be turned on.",
         "verified_closed"),
        ("payments-hub.internal.example:443", "core-banking-adapter", "infra/internal/payments-hub.tf",
         "RSA-2048 on the internal payments hub with a 10-year confidentiality lifetime",
         "Re-issue with RSA-3072 and enable TLS 1.3 on the internal listener.",
         "verified_closed"),
        ("payments.example.com:443", "payments-api", "deploy/tls/payments-ingress.yaml",
         "RSA-2048 certificate below the 3072-bit policy floor on a tier-1 payments endpoint",
         "Re-issue the payments ingress certificate at RSA-3072 and record the provider's hybrid key-exchange support.",
         "pr_created"),
        ("secure.example.com:443", "edge-gateway", "infra/edge/secure-tls.tf",
         "RSA-2048 on the customer secure portal",
         "Move the portal to ECDSA P-384 and pin the TLS 1.3 group list so a hybrid group can be added.",
         "pr_created"),
        ("ldap.internal.example:636", "infra-terraform", "infra/identity/ldap.tf",
         "Directory TLS still negotiates TLS 1.2 with a legacy cipher accepted",
         "Enable TLS 1.3 on the directory listener and drop the SHA-1 cipher suites.",
         "approved"),
        ("mq.internal.example:5671", "infra-terraform", "infra/messaging/mq.tf",
         "Message broker TLS 1.2-only with RSA-2048",
         "Enable TLS 1.3 on the broker and schedule the key rotation with the core banking release.",
         "approved"),
        ("reporting.internal.example:443", "core-banking-adapter", "infra/internal/reporting.tf",
         "Regulatory reporting service below the policy key floor",
         "Re-issue at RSA-3072 and link the change to the regulatory reporting release train.",
         "suggested"),
        ("partner.example.com:443", "partner-portal", "deploy/tls/partner-ingress.yaml",
         "Partner portal certificate expires in under 21 days",
         "Renew the partner ingress certificate and move issuance into the automated PKI pipeline.",
         "suggested"),
        ("treasury.example.com:443", "core-banking-adapter", "infra/edge/treasury-tls.tf",
         "Treasury endpoint has no recorded hybrid key-exchange plan",
         "Record the TLS termination point and add the hybrid group once the terminator supports it.",
         "suggested"),
    ]
    made = []
    for asset_key, repo, path, title, fix, status in remediation_plan:
        original = f"# {path}\nmin_tls_version = \"1.2\"\nkey_algorithm   = \"rsa-2048\"\ncrypto_owner    = \"\"\n"
        suggested = f"# {path}\nmin_tls_version = \"1.3\"\nkey_algorithm   = \"rsa-3072\"\ncrypto_owner    = \"platform-security\"\npqc_stage       = \"hybrid-group-pending\"\n"
        row = dbmod.create_remediation(
            asset_key, repo_ids.get(repo, 0), path, title, fix,
            original_content=original, suggested_content=suggested,
            status=status, review_note="Reviewed in the weekly crypto migration forum.",
            origin_kind="scan_finding",
        )
        made.append((int(row.get("id") or 0), status))
        if status in {"pr_created", "verified_closed"}:
            v = dbmod.create_validation_job(
                int(row.get("id") or 0), validator_type="terraform", git_ref="main",
                status="passed", job_id=f"val-{row.get('id')}",
                details={"commands": [
                    {"cmd": "terraform fmt -check", "exit_code": 0},
                    {"cmd": "terraform validate", "exit_code": 0},
                ], "iac_policy": {"status": "passed", "findings": []}},
            )
            dbmod.update_validation_job(int(v.get("id") or 0), status="passed",
                                        stdout="Validation passed.\n", stderr="", exit_code=0, finished=True)
    log(f"remediations: {len(made)} across suggested / approved / pr_created / verified_closed")

    # Give the estate a history: an asset was first seen at the scan that found
    # it, and a fix was raised, reviewed and closed over the weeks that followed.
    conn = sqlite3.connect(str(DEMO_DB), timeout=30)
    try:
        for entry in ESTATE:
            host, port, *_rest = entry
            first = entry[11]
            seen = NOW - timedelta(days=SCAN_SPACING_DAYS * (SCAN_COUNT - 1 - min(first, 4)))
            conn.execute("UPDATE assets SET updated_at=? WHERE asset_key=?",
                         (seen.strftime("%Y-%m-%dT%H:%M:%SZ"), f"{host}:{port}"))
        ages = {"suggested": 6, "approved": 19, "pr_created": 33, "verified_closed": 61}
        for rid, status in made:
            created = NOW - timedelta(days=ages.get(status, 10), hours=rid)
            fields = {"created_at": created.strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "updated_at": (created + timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")}
            if status in {"pr_created", "verified_closed"}:
                fields["pr_url"] = f"https://github.com/example-financial/repo/pull/{100 + rid}"
                fields["pr_branch"] = f"pqc/remediation-{rid}"
                fields["pr_base_branch"] = "main"
            if status == "verified_closed":
                merged = created + timedelta(days=9)
                fields["merged_at"] = merged.strftime("%Y-%m-%dT%H:%M:%SZ")
                fields["closed_at"] = (merged + timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
                fields["verification_scan_id"] = scan_ids[-1] if scan_ids else ""
                fields["drift_status"] = "clear"
                fields["last_drift_checked_at"] = NOW.strftime("%Y-%m-%dT%H:%M:%SZ")
            sets = ", ".join(f"{k}=?" for k in fields)
            conn.execute(f"UPDATE remediations SET {sets} WHERE id=?", (*fields.values(), rid))
        conn.commit()
    finally:
        conn.close()

    # ---------------------------------------------------------- migration tasks
    for title, asset, status, owner in [
        ("Enable hybrid key exchange on the edge fleet", "www.example.com:443", "in_progress", "digital-platform"),
        ("Move certificate issuance to the automated PKI pipeline", "partner.example.com:443", "in_progress", "platform-security"),
        ("Raise the policy key floor to RSA-3072 across production", "payments.example.com:443", "planned", "platform-security"),
        ("Retire TLS 1.2-only internal listeners", "mq.internal.example:5671", "planned", "core-banking"),
    ]:
        api.post("/migration-tasks", {"title": title, "asset_key": asset, "status": status,
                                      "owner": owner, "priority": "high"})

    # ---------------------------------------------------------- canaries
    for tier, asset in [("alpha", "statements.example.com:443"),
                        ("beta", "secure.example.com:443"),
                        ("gamma", "payments.example.com:443"),
                        ("delta", "treasury.example.com:443"),
                        ("omega", "payments-hub.internal.example:443")]:
        api.post("/canaries/deploy", {"tier": tier, "asset_key": asset,
                                      "notes": f"{COMPANY} demo estate tripwire"})
    for asset in ["secure.example.com:443", "treasury.example.com:443", "payments-hub.internal.example:443"]:
        api.post("/hndl-canary-tokens", {"asset_key": asset, "label": f"HNDL canary for {asset}"})

    # ---------------------------------------------------------- policy
    api.post("/policies", {
        "name": "Example Financial TLS and key policy v3",
        "description": "Minimum TLS 1.3, RSA-3072 or ECDSA P-384, no legacy ciphers, hybrid key exchange where the terminator supports it.",
        "rules": {"minimum_tls_version": "1.3", "min_rsa_bits": 3072, "min_ec_bits": 384,
                  "require_owner": True, "require_repository_link": True},
    })

    log("seed complete")


if __name__ == "__main__":
    main()
