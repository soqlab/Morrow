"""
Secrets Manager Cryptographic Scanner

Scans external secrets managers for quantum-vulnerable cryptographic material:
  - HashiCorp Vault (KV, PKI, Transit engines)
  - AWS SSM Parameter Store / Secrets Manager
  - Azure Key Vault
  - Generic environment variables / .env files

For each discovered secret, determines:
  - Whether it contains a private key or certificate
  - The algorithm and key size
  - Quantum vulnerability classification
  - Remediation priority

This module performs READ-ONLY operations using caller-supplied credentials.
It never writes to or modifies any secrets manager.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# ── Quantum vulnerability assessment ─────────────────────────────────────────

def _assess_key(key_type: str, key_bits: int) -> Dict[str, Any]:
    """Classify a key's quantum vulnerability."""
    kt = key_type.lower().strip()

    if any(x in kt for x in ("ml-kem", "kyber", "ml-dsa", "dilithium", "slh-dsa", "sphincs", "falcon", "ntru")):
        return {"risk_level": "safe", "quantum_vulnerable": False,
                "reason": "Post-quantum algorithm — not vulnerable to Shor/Grover attacks"}

    if "rsa" in kt:
        if key_bits <= 1024:
            return {"risk_level": "critical", "quantum_vulnerable": True,
                    "reason": f"RSA-{key_bits} is breakable with ~{key_bits // 3} logical qubits (Shor's algorithm)"}
        if key_bits <= 2048:
            return {"risk_level": "high", "quantum_vulnerable": True,
                    "reason": "RSA-2048 requires ~4,000 logical qubits (Gidney & Ekerå 2021 estimate)"}
        if key_bits <= 4096:
            return {"risk_level": "medium", "quantum_vulnerable": True,
                    "reason": "RSA-4096 requires ~10,000 logical qubits — longer runway but still vulnerable"}
        return {"risk_level": "medium", "quantum_vulnerable": True,
                "reason": f"RSA-{key_bits} — vulnerable to future quantum attack"}

    if any(x in kt for x in ("ec", "ecdsa", "ecdh", "ed25519", "x25519", "p-256", "p-384", "p-521")):
        bits = key_bits if key_bits else 256
        if bits <= 256:
            return {"risk_level": "high", "quantum_vulnerable": True,
                    "reason": f"ECC-{bits} vulnerable via Shor's algorithm — ~{bits * 2}x faster quantum attack vs classical"}
        return {"risk_level": "medium", "quantum_vulnerable": True,
                "reason": f"ECC-{bits} — quantum-vulnerable, longer runway than RSA-2048"}

    if "dsa" in kt:
        return {"risk_level": "high", "quantum_vulnerable": True,
                "reason": "Classical DSA vulnerable to quantum discrete logarithm attack (Shor)"}

    if any(x in kt for x in ("aes-256", "chacha20", "aes-192")):
        return {"risk_level": "low", "quantum_vulnerable": False,
                "reason": "Symmetric key — Grover's reduces security to sqrt(2^keylen), 256-bit still 128-bit quantum secure"}

    if any(x in kt for x in ("aes-128", "des", "3des", "rc4", "md5", "sha1")):
        return {"risk_level": "medium", "quantum_vulnerable": True,
                "reason": "Weak or legacy algorithm — vulnerable to both classical and quantum attacks"}

    return {"risk_level": "unknown", "quantum_vulnerable": None,
            "reason": "Unable to determine quantum vulnerability from algorithm identifier"}


def _extract_pem_info(pem_value: str) -> Optional[Dict[str, Any]]:
    """Extract key type and size from a PEM block (best-effort, no crypto library)."""
    pem = pem_value.strip()
    header_patterns = [
        (r"-----BEGIN RSA PRIVATE KEY-----",   "RSA",  "private"),
        (r"-----BEGIN RSA PUBLIC KEY-----",    "RSA",  "public"),
        (r"-----BEGIN EC PRIVATE KEY-----",    "EC",   "private"),
        (r"-----BEGIN PRIVATE KEY-----",       "PKS8", "private"),
        (r"-----BEGIN CERTIFICATE-----",       "CERT", "cert"),
        (r"-----BEGIN PUBLIC KEY-----",        "PUB",  "public"),
        (r"-----BEGIN OPENSSH PRIVATE KEY-----","SSH", "private"),
    ]

    pem_type = None
    key_kind = None
    for pattern, ktype, kind in header_patterns:
        if re.search(pattern, pem):
            pem_type = ktype
            key_kind = kind
            break

    if not pem_type:
        return None

    # Extract base64 body and estimate key size from DER length
    body_match = re.search(r"-----BEGIN[^-]+-----(.+?)-----END", pem, re.DOTALL)
    if not body_match:
        return None
    try:
        der_bytes = base64.b64decode(body_match.group(1).replace("\n", "").replace(" ", ""))
        der_len = len(der_bytes)
        # Heuristic: RSA-2048 DER ≈ 1190 bytes, RSA-4096 ≈ 2349 bytes, EC-256 ≈ 121 bytes
        if pem_type in ("RSA", "PKS8") and der_len > 500:
            if der_len < 700:    estimated_bits = 1024
            elif der_len < 1400: estimated_bits = 2048
            elif der_len < 2500: estimated_bits = 3072
            else:                estimated_bits = 4096
            return {"key_type": "RSA", "key_bits": estimated_bits, "key_kind": key_kind}
        if pem_type in ("EC",):
            if der_len < 150:  estimated_bits = 256
            elif der_len < 220: estimated_bits = 384
            else:               estimated_bits = 521
            return {"key_type": "EC", "key_bits": estimated_bits, "key_kind": key_kind}
        if pem_type == "SSH":
            return {"key_type": "SSH_RSA_or_EC", "key_bits": 2048, "key_kind": "private"}
        if pem_type == "CERT":
            return {"key_type": "CERT", "key_bits": 0, "key_kind": "cert"}
    except Exception:
        pass
    return {"key_type": pem_type, "key_bits": 0, "key_kind": key_kind}


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode()[:512]).hexdigest()[:16]


# ── HashiCorp Vault scanner ───────────────────────────────────────────────────

def scan_vault(
    vault_addr: str,
    vault_token: str,
    mount_paths: Optional[List[str]] = None,
    pki_mounts: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Scan a HashiCorp Vault instance for quantum-vulnerable secrets.
    Uses Vault HTTP API (v1). Requires list + read permissions on target paths.

    vault_addr: e.g. "https://vault.example.com"
    vault_token: Vault token with list/read access
    mount_paths: KV paths to scan, e.g. ["secret/", "kv/"]
    pki_mounts: PKI engine mounts, e.g. ["pki/"]
    """
    vault_addr = vault_addr.rstrip("/")
    headers = {"X-Vault-Token": vault_token, "Content-Type": "application/json"}
    mount_paths = mount_paths or ["secret/"]
    pki_mounts = pki_mounts or []
    findings = []
    errors = []

    def _vault_request(path: str) -> Optional[Any]:
        url = f"{vault_addr}/v1/{path}"
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            if e.code not in (403, 404):
                errors.append(f"HTTP {e.code} on {path}")
            return None
        except Exception as ex:
            errors.append(f"Error on {path}: {str(ex)[:80]}")
            return None

    def _scan_kv_path(mount: str, sub_path: str = "") -> None:
        list_path = f"{mount}{sub_path}?list=true"
        data = _vault_request(list_path)
        if not data or "data" not in data:
            return
        keys = data["data"].get("keys", [])
        for key in keys[:50]:  # limit to prevent runaway
            full_key = f"{sub_path}{key}"
            if key.endswith("/"):
                _scan_kv_path(mount, full_key)
                continue
            secret_data = _vault_request(f"{mount}{full_key}")
            if not secret_data:
                continue
            secret_vals = secret_data.get("data", {})
            # Handle KV v2
            if "data" in secret_vals:
                secret_vals = secret_vals["data"]
            _check_secret_values(f"vault://{mount}{full_key}", secret_vals)

    def _check_secret_values(path: str, values: Dict[str, Any]) -> None:
        for key, value in values.items():
            if not isinstance(value, str):
                continue
            value.lower().strip()
            pem_info = None

            if "-----BEGIN" in value:
                pem_info = _extract_pem_info(value)
                if pem_info:
                    assessment = _assess_key(pem_info["key_type"], pem_info["key_bits"])
                    findings.append({
                        "source": "vault",
                        "path": path,
                        "field": key,
                        "key_type": pem_info["key_type"],
                        "key_bits": pem_info["key_bits"],
                        "key_kind": pem_info["key_kind"],
                        "fingerprint": _fingerprint(value),
                        **assessment,
                    })
            # Heuristic: key names suggesting crypto material
            elif any(kw in key.lower() for kw in
                     ("private_key", "priv_key", "rsa_key", "ec_key", "ssl_key",
                      "tls_key", "jwt_secret", "signing_key")):
                findings.append({
                    "source": "vault",
                    "path": path,
                    "field": key,
                    "key_type": "unknown (heuristic match)",
                    "key_bits": 0,
                    "key_kind": "private",
                    "fingerprint": _fingerprint(value[:32]),
                    "risk_level": "unknown",
                    "quantum_vulnerable": None,
                    "reason": "Field name suggests cryptographic key — manual review required",
                })

    for mount in mount_paths:
        if not mount.endswith("/"):
            mount += "/"
        _scan_kv_path(mount)

    for pki_mount in pki_mounts:
        pki_mount = pki_mount.rstrip("/")
        ca_data = _vault_request(f"{pki_mount}/cert/ca")
        if ca_data:
            cert_pem = ca_data.get("data", {}).get("certificate", "")
            if cert_pem and "-----BEGIN" in cert_pem:
                pem_info = _extract_pem_info(cert_pem)
                if pem_info:
                    assessment = _assess_key(pem_info["key_type"], pem_info["key_bits"])
                    findings.append({
                        "source": "vault_pki",
                        "path": f"vault://{pki_mount}/cert/ca",
                        "field": "ca_certificate",
                        "key_type": pem_info["key_type"],
                        "key_bits": pem_info["key_bits"],
                        "key_kind": "ca",
                        "fingerprint": _fingerprint(cert_pem),
                        **assessment,
                    })

    return _summarize_findings("HashiCorp Vault", findings, errors)


# ── AWS scanner (SSM + Secrets Manager) ──────────────────────────────────────

def scan_aws(
    aws_access_key_id: str,
    aws_secret_access_key: str,
    aws_region: str = "us-east-1",
    scan_ssm: bool = True,
    scan_secrets_manager: bool = True,
    path_prefix: str = "/",
) -> Dict[str, Any]:
    """
    Scan AWS SSM Parameter Store and Secrets Manager for quantum-vulnerable keys.
    Uses AWS SDK via urllib (SigV4 signing would be required in prod; this
    implementation uses pre-generated session tokens or boto3 for production use).

    NOTE: In production, supply boto3 credentials via IAM role; this method
    accepts explicit credentials for air-gapped / self-hosted deployments.
    """
    findings = []
    errors = []

    try:
        import boto3
        session = boto3.Session(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name=aws_region,
        )

        if scan_ssm:
            ssm = session.client("ssm")
            paginator = ssm.get_paginator("get_parameters_by_path")
            try:
                for page in paginator.paginate(
                    Path=path_prefix,
                    Recursive=True,
                    WithDecryption=True,
                    PaginationConfig={"MaxItems": 200},
                ):
                    for param in page.get("Parameters", []):
                        value = param.get("Value", "")
                        name = param.get("Name", "")
                        if "-----BEGIN" in value:
                            pem_info = _extract_pem_info(value)
                            if pem_info:
                                assessment = _assess_key(pem_info["key_type"], pem_info["key_bits"])
                                findings.append({
                                    "source": "aws_ssm",
                                    "path": f"ssm://{name}",
                                    "field": name.split("/")[-1],
                                    "key_type": pem_info["key_type"],
                                    "key_bits": pem_info["key_bits"],
                                    "key_kind": pem_info["key_kind"],
                                    "fingerprint": _fingerprint(value),
                                    **assessment,
                                })
            except Exception as e:
                errors.append(f"SSM scan error: {str(e)[:100]}")

        if scan_secrets_manager:
            sm = session.client("secretsmanager")
            try:
                paginator = sm.get_paginator("list_secrets")
                for page in paginator.paginate(PaginationConfig={"MaxItems": 100}):
                    for secret_meta in page.get("SecretList", []):
                        arn = secret_meta.get("ARN", "")
                        try:
                            secret_val = sm.get_secret_value(SecretId=arn)
                            value = secret_val.get("SecretString", "")
                            if not value:
                                continue

                            secret_name = secret_meta.get("Name", arn)

                            # Try the JSON envelope FIRST.
                            #
                            # Secrets Manager usually stores a JSON object with the
                            # key as one field. The old order tested the raw string
                            # for "-----BEGIN" before attempting to parse it -- and
                            # a JSON blob containing a PEM contains that marker, so
                            # the bare-PEM branch always won and the envelope branch
                            # was unreachable for the only input it existed to
                            # handle. Three consequences, all silent:
                            #   * only one key was reported from a bundle of several;
                            #   * it was attributed to "secret_string" rather than
                            #     the field, so remediation pointed at the wrong
                            #     thing;
                            #   * _extract_pem_info ran against the whole blob and
                            #     returned key_bits 0, which _assess_key renders as
                            #     "RSA-0 ... breakable with ~0 logical qubits" -- a
                            #     false critical on a healthy RSA-2048 key.
                            parsed = None
                            if value.lstrip().startswith("{"):
                                try:
                                    candidate = json.loads(value)
                                    if isinstance(candidate, dict):
                                        parsed = candidate
                                except (ValueError, TypeError):
                                    parsed = None

                            if parsed is not None:
                                for fld, fval in parsed.items():
                                    if not isinstance(fval, str) or "-----BEGIN" not in fval:
                                        continue
                                    pem_info = _extract_pem_info(fval)
                                    if not pem_info:
                                        continue
                                    assessment = _assess_key(pem_info["key_type"], pem_info["key_bits"])
                                    findings.append({
                                        "source": "aws_secrets_manager",
                                        "path": f"sm://{secret_name}",
                                        "field": fld,
                                        "key_type": pem_info["key_type"],
                                        "key_bits": pem_info["key_bits"],
                                        "key_kind": pem_info["key_kind"],
                                        "fingerprint": _fingerprint(fval),
                                        **assessment,
                                    })
                            elif "-----BEGIN" in value:
                                pem_info = _extract_pem_info(value)
                                if pem_info:
                                    assessment = _assess_key(pem_info["key_type"], pem_info["key_bits"])
                                    findings.append({
                                        "source": "aws_secrets_manager",
                                        "path": f"sm://{secret_name}",
                                        "field": "secret_string",
                                        "key_type": pem_info["key_type"],
                                        "key_bits": pem_info["key_bits"],
                                        "key_kind": pem_info["key_kind"],
                                        "fingerprint": _fingerprint(value),
                                        **assessment,
                                    })
                        except Exception:
                            pass
            except Exception as e:
                errors.append(f"Secrets Manager scan error: {str(e)[:100]}")

    except ImportError:
        errors.append("boto3 not installed — install boto3 to enable AWS scanning")
    except Exception as e:
        errors.append(f"AWS connection error: {str(e)[:100]}")

    return _summarize_findings("AWS SSM / Secrets Manager", findings, errors)


# ── Azure Key Vault scanner ───────────────────────────────────────────────────

def scan_azure_key_vault(
    vault_url: str,
    tenant_id: str,
    client_id: str,
    client_secret: str,
) -> Dict[str, Any]:
    """
    Scan an Azure Key Vault instance for quantum-vulnerable keys and certificates.
    Uses Azure REST API with client credentials flow.

    vault_url: e.g. "https://myvault.vault.azure.net"
    """
    findings = []
    errors = []

    # Get access token via client credentials
    def _get_token() -> Optional[str]:
        token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        body = (
            f"grant_type=client_credentials"
            f"&client_id={urllib.parse.quote(client_id)}"
            f"&client_secret={urllib.parse.quote(client_secret)}"
            f"&scope=https%3A%2F%2Fvault.azure.net%2F.default"
        ).encode()
        try:
            req = urllib.request.Request(token_url, data=body,
                                         headers={"Content-Type": "application/x-www-form-urlencoded"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read().decode()).get("access_token")
        except Exception as e:
            errors.append(f"Azure token error: {str(e)[:80]}")
            return None

    import urllib.parse

    token = _get_token()
    if not token:
        return _summarize_findings("Azure Key Vault", findings, errors)

    headers = {"Authorization": f"Bearer {token}"}
    vault_url = vault_url.rstrip("/")

    def _az_get(path: str) -> Optional[Any]:
        url = f"{vault_url}/{path}?api-version=7.4"
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            if e.code not in (403, 404):
                errors.append(f"Azure HTTP {e.code}: {path}")
            return None
        except Exception as e:
            errors.append(f"Azure request error: {str(e)[:80]}")
            return None

    # Scan keys
    keys_list = _az_get("keys")
    if keys_list:
        for key_item in keys_list.get("value", [])[:50]:
            key_id = key_item.get("kid", "")
            key_name = key_id.split("/")[-1] if "/" in key_id else key_id
            key_detail = _az_get(f"keys/{key_name}")
            if key_detail:
                kty = key_detail.get("key", {}).get("kty", "")
                key_size = key_detail.get("key", {}).get("key_size")
                n = key_detail.get("key", {}).get("n", "")
                # Infer bits from modulus length for RSA
                if n and not key_size:
                    try:
                        key_size = len(base64.urlsafe_b64decode(n + "==")) * 8
                    except Exception:
                        key_size = 2048

                key_type_map = {"RSA": "RSA", "EC": "EC", "RSA-HSM": "RSA", "EC-HSM": "EC",
                                "oct": "AES", "oct-HSM": "AES"}
                kt = key_type_map.get(kty, kty)
                kb = key_size or 256
                assessment = _assess_key(kt, kb)
                findings.append({
                    "source": "azure_key_vault",
                    "path": f"akv://keys/{key_name}",
                    "field": "key",
                    "key_type": kt,
                    "key_bits": kb,
                    "key_kind": "private",
                    "fingerprint": _fingerprint(key_id),
                    **assessment,
                })

    # Scan certificates
    certs_list = _az_get("certificates")
    if certs_list:
        for cert_item in certs_list.get("value", [])[:50]:
            cert_id = cert_item.get("id", "")
            cert_name = cert_id.rstrip("/").split("/")[-1]
            cert_detail = _az_get(f"certificates/{cert_name}")
            if cert_detail:
                policy = cert_detail.get("policy", {})
                key_props = policy.get("key_props", {})
                kty = key_props.get("kty", "RSA")
                ksize = key_props.get("key_size", 2048)
                kt = "RSA" if "RSA" in kty else "EC"
                assessment = _assess_key(kt, ksize)
                findings.append({
                    "source": "azure_key_vault",
                    "path": f"akv://certificates/{cert_name}",
                    "field": "certificate",
                    "key_type": kt,
                    "key_bits": ksize,
                    "key_kind": "cert",
                    "fingerprint": _fingerprint(cert_id),
                    **assessment,
                })

    return _summarize_findings("Azure Key Vault", findings, errors)


# ── Environment file scanner ──────────────────────────────────────────────────

def _logical_env_lines(env_content: str) -> List[str]:
    """Split env content into assignments, keeping a multi-line PEM value with its variable.

    A PEM block in a .env file may be written either with escaped newlines on one line or spread
    across real lines (dotenv and most config tooling accept both, and an environment dump keeps
    whatever was set). Splitting purely on newlines tore the second form apart: only the header line
    carried the variable name, so the PEM body never reached the parser, extraction failed, and the
    name-based fallback was skipped as well -- because that first line does contain "-----BEGIN".
    The result was a real private key in a config file reported as no finding at all, silently.
    """
    logical: List[str] = []
    buffer: Optional[str] = None
    for raw in env_content.splitlines():
        if buffer is not None:
            buffer += "\n" + raw
            if "-----END" in raw:
                logical.append(buffer)
                buffer = None
            continue
        if "=" in raw and "-----BEGIN" in raw.partition("=")[2] and "-----END" not in raw:
            buffer = raw
            continue
        logical.append(raw)
    if buffer is not None:  # unterminated block: keep what we have rather than dropping it
        logical.append(buffer)
    return logical


def scan_env_content(env_content: str, source_name: str = "env_file") -> Dict[str, Any]:
    """
    Scan the content of a .env file or environment variable dump for
    quantum-vulnerable keys.
    """
    findings = []
    errors = []
    lines = _logical_env_lines(env_content)

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip().strip('"').strip("'")

        if "-----BEGIN" in value:
            full_pem = value.replace("\\n", "\n")
            pem_info = _extract_pem_info(full_pem)
            if pem_info:
                assessment = _assess_key(pem_info["key_type"], pem_info["key_bits"])
                findings.append({
                    "source": source_name,
                    "path": source_name,
                    "field": key.strip(),
                    "key_type": pem_info["key_type"],
                    "key_bits": pem_info["key_bits"],
                    "key_kind": pem_info["key_kind"],
                    "fingerprint": _fingerprint(value[:64]),
                    **assessment,
                })
        elif any(kw in key.lower() for kw in
                 ("private_key", "priv_key", "rsa_key", "ec_key", "ssl_key",
                  "signing_key", "jwt_secret")):
            if len(value) > 32:  # non-trivial value
                findings.append({
                    "source": source_name,
                    "path": source_name,
                    "field": key.strip(),
                    "key_type": "unknown (env heuristic)",
                    "key_bits": 0,
                    "key_kind": "unknown",
                    "fingerprint": _fingerprint(value[:32]),
                    "risk_level": "unknown",
                    "quantum_vulnerable": None,
                    "reason": "Variable name suggests cryptographic key — decode and inspect manually",
                })

    return _summarize_findings(source_name, findings, errors)


# ── Summary builder ───────────────────────────────────────────────────────────

def _summarize_findings(source_name: str, findings: List[Dict], errors: List[str]) -> Dict[str, Any]:
    critical = [f for f in findings if f.get("risk_level") == "critical"]
    high     = [f for f in findings if f.get("risk_level") == "high"]
    medium   = [f for f in findings if f.get("risk_level") == "medium"]
    low      = [f for f in findings if f.get("risk_level") == "low"]
    safe     = [f for f in findings if f.get("risk_level") == "safe"]
    unknown  = [f for f in findings if f.get("risk_level") == "unknown"]

    quantum_vulnerable = [f for f in findings if f.get("quantum_vulnerable")]

    return {
        "source": source_name,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(findings),
        "quantum_vulnerable_count": len(quantum_vulnerable),
        "summary": {
            "critical": len(critical),
            "high": len(high),
            "medium": len(medium),
            "low": len(low),
            "safe": len(safe),
            "unknown": len(unknown),
        },
        "findings": findings,
        "errors": errors,
        "remediation_priority": (
            "IMMEDIATE" if critical else
            "HIGH"      if high else
            "MEDIUM"    if medium else
            "LOW"       if quantum_vulnerable else
            "NONE"
        ),
    }


def aggregate_scan_results(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Merge results from multiple scanner runs into a unified view."""
    all_findings = []
    for r in results:
        all_findings.extend(r.get("findings", []))
    total_errors = [e for r in results for e in r.get("errors", [])]

    summary = _summarize_findings("aggregate", all_findings, total_errors)
    summary["sources_scanned"] = [r.get("source", "unknown") for r in results]
    return summary
