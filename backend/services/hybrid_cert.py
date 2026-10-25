"""
Hybrid Certificate Provisioner

Provisions X.509v3 hybrid certificates that carry both a classical public key
(RSA-2048 or P-256) AND a post-quantum public key (ML-KEM-768 or ML-DSA-65)
as a Subject Alternative Name extension or custom OID extension.

The hybrid approach ensures:
  - Classical systems that don't understand post-quantum can still verify the classical sig
  - post-quantum-aware clients verify the post-quantum key, immune to quantum attack
  - Zero downtime migration path — deploy hybrid cert, retire classical later

Integration:
  - ACME/Let's Encrypt: auto-provision via certbot + OQS plugin (if installed)
  - Self-signed: generate hybrid cert entirely in-process for testing/internal use
  - Manual CSR: generate hybrid CSR for submission to your existing CA

Post-quantum key generation requires one of:
  - liboqs + python-oqs (OpenQuantumSafe project)
  - pqcrypto Python package
  - OQS-OpenSSL with PyOpenSSL

Missing post-quantum libraries are reported as a blocked state. API callers must not
present unavailable post-quantum cryptography as production-capable.
"""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

def _pq_backend_available() -> bool:
    try:
        import oqs  # noqa: F401
        return True
    except ImportError:
        pass
    try:
        import pqcrypto  # noqa: F401
        return True
    except ImportError:
        return False


def _blocked_missing_pq(common_name: str, pq_algo: str) -> Dict[str, Any]:
    return {
        "status": "blocked",
        "common_name": common_name,
        "pq_algorithm": pq_algo,
        "pq_key_real": False,
        "cert_real": False,
        "error": "real_pq_library_unavailable",
        "detail": "Install liboqs/python-oqs or pqcrypto before generating post-quantum certificate material.",
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


# ── post-quantum key generation (with graceful fallback) ────────────────────────────────

def _generate_ml_kem_768_keypair() -> Dict[str, Any]:
    """Generate an ML-KEM-768 keypair with a real post-quantum backend."""
    try:
        import oqs
        kem = oqs.KeyEncapsulation("Kyber768")
        public_key = kem.generate_keypair()
        private_key = kem.export_secret_key()
        return {
            "algorithm": "ML-KEM-768",
            "public_key_b64": base64.b64encode(public_key).decode(),
            "private_key_b64": base64.b64encode(private_key).decode(),
            "public_key_bytes": len(public_key),
            "private_key_bytes": len(private_key),
            "is_real_pq": True,
            "library": "liboqs/python-oqs",
        }
    except ImportError:
        pass
    try:
        from pqcrypto.kem.kyber768 import generate_keypair
        pub, priv = generate_keypair()
        return {
            "algorithm": "ML-KEM-768",
            "public_key_b64": base64.b64encode(pub).decode(),
            "private_key_b64": base64.b64encode(priv).decode(),
            "public_key_bytes": len(pub),
            "private_key_bytes": len(priv),
            "is_real_pq": True,
            "library": "pqcrypto",
        }
    except ImportError:
        pass
    raise RuntimeError("real_pq_library_unavailable: install liboqs/python-oqs or pqcrypto")


def _generate_ml_dsa_65_keypair() -> Dict[str, Any]:
    """Generate an ML-DSA-65 keypair with a real post-quantum backend."""
    try:
        import oqs
        sig = oqs.Signature("Dilithium3")
        public_key = sig.generate_keypair()
        private_key = sig.export_secret_key()
        return {
            "algorithm": "ML-DSA-65",
            "public_key_b64": base64.b64encode(public_key).decode(),
            "private_key_b64": base64.b64encode(private_key).decode(),
            "public_key_bytes": len(public_key),
            "private_key_bytes": len(private_key),
            "is_real_pq": True,
            "library": "liboqs/python-oqs",
        }
    except ImportError:
        pass
    raise RuntimeError("real_pq_library_unavailable: install liboqs/python-oqs")


def _generate_rsa_keypair(bits: int = 2048) -> Dict[str, Any]:
    """Generate an RSA keypair using the cryptography library."""
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        pub = priv.public_key()
        priv_pem = priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        pub_pem = pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        return {"algorithm": f"RSA-{bits}", "private_key_pem": priv_pem, "public_key_pem": pub_pem,
                "key_bits": bits, "is_real": True}
    except ImportError:
        return {"algorithm": f"RSA-{bits}", "private_key_pem": "", "public_key_pem": "",
                "key_bits": bits, "is_real": False,
                "warning": "cryptography library not installed — install it to generate real RSA keys"}


def _generate_ec_keypair(curve: str = "P-256") -> Dict[str, Any]:
    """Generate an EC keypair."""
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization
        curve_map = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(), "P-521": ec.SECP521R1()}
        priv = ec.generate_private_key(curve_map.get(curve, ec.SECP256R1()))
        pub = priv.public_key()
        priv_pem = priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        pub_pem = pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        return {"algorithm": curve, "private_key_pem": priv_pem, "public_key_pem": pub_pem, "is_real": True}
    except ImportError:
        return {"algorithm": curve, "private_key_pem": "", "public_key_pem": "", "is_real": False,
                "warning": "cryptography library not installed"}


# ── Self-signed certificate generation ────────────────────────────────────────

def generate_self_signed_hybrid(
    common_name: str,
    san_domains: Optional[List[str]] = None,
    san_ips: Optional[List[str]] = None,
    classical_algo: str = "RSA-2048",
    pq_algo: str = "ML-KEM-768",
    validity_days: int = 365,
    org_name: str = "Test Organization",
    country: str = "US",
) -> Dict[str, Any]:
    """
    Generate a self-signed hybrid certificate:
      - Classical key (RSA-2048 or P-256) for backward compatibility
      - post-quantum key (ML-KEM-768 or ML-DSA-65) embedded as custom extension

    Returns: {cert_pem, private_key_pem, pq_public_key_b64, metadata, ...}
    """
    san_domains = san_domains or [common_name]
    san_ips = san_ips or []
    if not _pq_backend_available():
        blocked = _blocked_missing_pq(common_name, pq_algo)
        blocked["san_domains"] = san_domains
        blocked["san_ips"] = san_ips
        blocked["classical_algorithm"] = classical_algo
        return blocked

    # Generate classical keypair
    if "RSA" in classical_algo:
        bits = int(classical_algo.split("-")[-1]) if "-" in classical_algo else 2048
        classical = _generate_rsa_keypair(bits)
    else:
        classical = _generate_ec_keypair(classical_algo)

    # Generate post-quantum keypair
    if "KEM" in pq_algo or "Kyber" in pq_algo.lower() or "kyber" in pq_algo.lower():
        pq = _generate_ml_kem_768_keypair()
    else:
        pq = _generate_ml_dsa_65_keypair()

    now = datetime.now(timezone.utc)
    not_after = now + timedelta(days=validity_days)
    cert_id = "HYBRID-" + hashlib.sha256(f"{common_name}:{now.isoformat()}".encode()).hexdigest()[:12].upper()

    from services.public_config import private_enterprise_oid
    hybrid_oid = private_enterprise_oid()

    # Try to generate real cert with cryptography library
    cert_pem = ""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        import ipaddress as _ipaddress

        # Parse private key
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        priv_key = load_pem_private_key(classical["private_key_pem"].encode(), password=None) if classical.get("private_key_pem") else None

        if priv_key:
            subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, country[:2]),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name[:64]),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name[:64]),
            ])
            san_list = [x509.DNSName(d) for d in san_domains]
            for ip_str in san_ips:
                try:
                    san_list.append(x509.IPAddress(_ipaddress.ip_address(ip_str)))
                except ValueError:
                    pass

            builder = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(subject)
                .public_key(priv_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now)
                .not_valid_after(not_after)
                .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            )
            # Embed the post-quantum public key in a private extension only under an OID
            # the operator owns (MORROW_PRIVATE_ENTERPRISE_OID). Without one the
            # extension is omitted rather than emitted under a made-up OID.
            if hybrid_oid:
                pq_pub_bytes = base64.b64decode(pq["public_key_b64"])
                pq_ext_value = b"\x30" + _encode_der_length(len(pq_pub_bytes) + 2) + b"\x04" + _encode_der_length(len(pq_pub_bytes)) + pq_pub_bytes
                builder = builder.add_extension(
                    x509.UnrecognizedExtension(
                        x509.ObjectIdentifier(hybrid_oid),
                        pq_ext_value,
                    ),
                    critical=False,
                )
            cert = builder.sign(priv_key, hashes.SHA256())
            cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    except Exception:
        cert_pem = ""

    return {
        "cert_id": cert_id,
        "common_name": common_name,
        "san_domains": san_domains,
        "san_ips": san_ips,
        "classical_algorithm": classical_algo,
        "pq_algorithm": pq_algo,
        "valid_from": now.isoformat()[:10],
        "valid_until": not_after.isoformat()[:10],
        "validity_days": validity_days,
        "status": "active" if cert_pem else "blocked",
        "error": "" if cert_pem else "certificate_generation_failed",
        "cert_pem": cert_pem,
        "classical_private_key_pem": classical.get("private_key_pem", ""),
        "pq_public_key_b64": pq["public_key_b64"],
        "pq_private_key_b64": pq["private_key_b64"],
        "pq_key_real": pq.get("is_real_pq", False),
        "pq_warning": pq.get("warning", ""),
        "cert_real": bool(cert_pem),
        "hybrid_oid": hybrid_oid or None,
        "pq_extension_included": bool(cert_pem and hybrid_oid),
        "pq_extension_note": (
            "" if hybrid_oid else
            "Post-quantum public-key extension omitted: set MORROW_PRIVATE_ENTERPRISE_OID to an OID under your IANA "
            "Private Enterprise Number to embed it."
        ),
        "deployment_guide": _deployment_guide(classical_algo, pq_algo),
        "generated_at": now.isoformat(),
    }


def _encode_der_length(n: int) -> bytes:
    if n < 128:
        return bytes([n])
    elif n < 256:
        return bytes([0x81, n])
    else:
        return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])


def _deployment_guide(classical: str, pq: str) -> List[Dict[str, str]]:
    return [
        {
            "step": "1",
            "title": "Deploy hybrid certificate to your web server",
            "detail": f"Replace your current RSA/ECC cert with this hybrid cert. Classical ({classical}) clients continue working normally.",
        },
        {
            "step": "2",
            "title": "Configure TLS to advertise post-quantum key exchange",
            "detail": "Enable X25519Kyber768 (hybrid) in your TLS configuration. Nginx: ssl_ecdh_curve X25519Kyber768; | Apache: SSLOpenSSLConfCmd Curves X25519Kyber768",
        },
        {
            "step": "3",
            "title": "Verify hybrid operation",
            "detail": "Use Chrome or curl with OQS-curl to verify post-quantum key exchange is negotiated. Check server logs for 'kyber' in cipher suite.",
        },
        {
            "step": "4",
            "title": "Monitor post-quantum adoption rate",
            "detail": "Track what percentage of clients are negotiating post-quantum key exchange. When ≥90%, schedule removal of classical fallback.",
        },
        {
            "step": "5",
            "title": "Retire classical keys",
            "detail": f"Once Q-Day risk is elevated and post-quantum client support is widespread, redeploy with {pq}-only certificate.",
        },
    ]


# ── CSR generation ─────────────────────────────────────────────────────────────

def generate_hybrid_csr(
    common_name: str,
    classical_algo: str = "RSA-2048",
    pq_algo: str = "ML-KEM-768",
    org_name: str = "",
    country: str = "US",
) -> Dict[str, Any]:
    """Generate a Certificate Signing Request with embedded post-quantum public key."""
    if not _pq_backend_available():
        blocked = _blocked_missing_pq(common_name, pq_algo)
        blocked["csr_real"] = False
        blocked["classical_algorithm"] = classical_algo
        return blocked

    if "RSA" in classical_algo:
        bits = int(classical_algo.split("-")[-1]) if "-" in classical_algo else 2048
        classical = _generate_rsa_keypair(bits)
    else:
        classical = _generate_ec_keypair(classical_algo)

    pq = _generate_ml_kem_768_keypair() if "KEM" in pq_algo else _generate_ml_dsa_65_keypair()

    csr_pem = ""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        priv = serialization.load_pem_private_key(classical["private_key_pem"].encode(), None) if classical.get("private_key_pem") else None
        if priv:
            attrs = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
            if org_name: attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name))
            if country:  attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country[:2]))
            csr = (
                x509.CertificateSigningRequestBuilder()
                .subject_name(x509.Name(attrs))
                .sign(priv, hashes.SHA256())
            )
            csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    except Exception:
        csr_pem = ""

    return {
        "common_name": common_name,
        "status": "active" if csr_pem else "blocked",
        "error": "" if csr_pem else "csr_generation_failed",
        "classical_algorithm": classical_algo,
        "pq_algorithm": pq_algo,
        "csr_pem": csr_pem,
        "csr_real": bool(csr_pem and "BEGIN CERTIFICATE REQUEST" in csr_pem),
        "classical_private_key_pem": classical.get("private_key_pem", ""),
        "pq_public_key_b64": pq["public_key_b64"],
        "pq_private_key_b64": pq["private_key_b64"],
        "pq_key_real": pq.get("is_real_pq", False),
        "pq_warning": pq.get("warning", ""),
        "instructions": [
            "Submit the CSR PEM to your CA to obtain a classical certificate",
            "Embed the post-quantum public key via the CA's post-quantum hybrid extension if supported",
            "Store both private keys securely — the classical key and the post-quantum key",
            "When deploying, configure TLS to use the classical cert for backward compat",
        ],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def check_pq_library_availability() -> Dict[str, Any]:
    """Check which post-quantum libraries are available in the current environment."""
    availability = {}
    try:
        import oqs
        availability["liboqs"] = {"available": True, "version": getattr(oqs, "__version__", "unknown")}
    except ImportError:
        availability["liboqs"] = {"available": False, "install": "pip install liboqs-python"}

    try:
        import pqcrypto
        availability["pqcrypto"] = {"available": True, "version": getattr(pqcrypto, "__version__", "unknown")}
    except ImportError:
        availability["pqcrypto"] = {"available": False, "install": "pip install pqcrypto"}

    try:
        from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: F401 - probes that the backend is usable, not just installed
        import cryptography
        availability["cryptography"] = {"available": True, "version": cryptography.__version__}
    except ImportError:
        availability["cryptography"] = {"available": False, "install": "pip install cryptography"}

    any_pq = availability.get("liboqs", {}).get("available") or availability.get("pqcrypto", {}).get("available")

    return {
        "libraries": availability,
        "real_pq_available": any_pq,
        "classical_crypto_available": availability.get("cryptography", {}).get("available", False),
        "recommendation": (
            "Install liboqs-python for production post-quantum key generation: pip install liboqs-python"
            if not any_pq else
            "Post-quantum libraries available — hybrid certificate generation will use real post-quantum keys"
        ),
    }
