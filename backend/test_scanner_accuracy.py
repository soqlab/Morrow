"""Known-answer tests for TLS scanning accuracy.

A crypto-inventory tool's core claim is that what it reports is what is actually deployed. Until now
nothing checked that: the suite exercised endpoints, storage, and reporting, but never asked whether
a scan of a known certificate produces the right algorithm, key size, and signature.

Ground truth here is not an expert opinion — these tests *generate* the certificates, so the correct
answer is known by construction. Each case starts a real TLS server on loopback with a
freshly-minted certificate and scans it through the same scanner.scan_host() the product uses.

Scope: classical algorithms, which is what `cryptography` can mint. Post-quantum certificates
(ML-DSA, SLH-DSA) need a PQC-capable TLS stack and stay out of scope; the CBOM side of those is
covered by test_cbom_conformance.py.
"""
from __future__ import annotations

import datetime
import os
import socket
import ssl
import threading
from typing import Any, Dict, Tuple

import pytest

cryptography = pytest.importorskip("cryptography", reason="cryptography is required to mint test certificates")

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

import scanner


def _self_signed(key, public_key, sig_hash, common_name: str) -> bytes:
    """A minimal self-signed certificate, PEM encoded."""
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    cert = builder.sign(key, sig_hash)
    return cert.public_bytes(serialization.Encoding.PEM)


def _key_pem(key) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _make_rsa(bits: int, digest) -> Tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return _key_pem(key), _self_signed(key, key.public_key(), digest, f"rsa{bits}.test")


def _make_ec(curve, digest) -> Tuple[bytes, bytes]:
    key = ec.generate_private_key(curve)
    return _key_pem(key), _self_signed(key, key.public_key(), digest, f"{curve.name}.test")


def _make_ed25519() -> Tuple[bytes, bytes]:
    key = ed25519.Ed25519PrivateKey.generate()
    # Ed25519 certificates carry no separate digest; the algorithm fixes it.
    return _key_pem(key), _self_signed(key, key.public_key(), None, "ed25519.test")


class _TlsServer:
    """A throwaway TLS server on loopback, serving one certificate."""

    def __init__(self, cert_pem: bytes, key_pem: bytes, tls_version: Any = None) -> None:
        self._cert_pem, self._key_pem = cert_pem, key_pem
        self._tls_version = tls_version
        self.port = 0
        self._sock: Any = None
        self._thread: Any = None
        self._stop = threading.Event()

    def __enter__(self) -> "_TlsServer":
        import tempfile

        cert_file = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
        cert_file.write(self._cert_pem)
        cert_file.close()
        key_file = tempfile.NamedTemporaryFile(suffix=".key", delete=False)
        key_file.write(self._key_pem)
        key_file.close()
        self._files = (cert_file.name, key_file.name)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        if self._tls_version is not None:
            context.minimum_version = self._tls_version
            context.maximum_version = self._tls_version
        context.load_cert_chain(cert_file.name, key_file.name)

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]

        def serve() -> None:
            while not self._stop.is_set():
                try:
                    self._sock.settimeout(0.5)
                    raw, _ = self._sock.accept()
                except (socket.timeout, OSError):
                    continue
                try:
                    with context.wrap_socket(raw, server_side=True) as tls:
                        try:
                            tls.recv(1024)
                            tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                        except OSError:
                            pass
                except (ssl.SSLError, OSError):
                    pass

        self._thread = threading.Thread(target=serve, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        if self._thread:
            self._thread.join(timeout=3)
        for path in getattr(self, "_files", ()):
            try:
                os.unlink(path)
            except OSError:
                pass


def _scan(cert_pem: bytes, key_pem: bytes, tls_version: Any = None) -> Dict[str, Any]:
    with _TlsServer(cert_pem, key_pem, tls_version) as server:
        return scanner.scan_host("127.0.0.1", server.port)


# --------------------------------------------------------------------------------------------
# Public key type and size
# --------------------------------------------------------------------------------------------

@pytest.mark.parametrize("bits", [2048, 3072])
def test_rsa_key_size_is_reported_exactly(bits):
    """An RSA key's size drives every downstream risk judgement, so it must be exact."""
    key_pem, cert_pem = _make_rsa(bits, hashes.SHA256())

    facts = _scan(cert_pem, key_pem)

    assert not facts.get("error"), facts.get("error")
    assert facts["key_type"] == "RSA", f"reported key_type {facts['key_type']!r}"
    assert str(bits) in str(facts.get("key_detail") or ""), (
        f"RSA-{bits} reported key_detail {facts.get('key_detail')!r}"
    )


@pytest.mark.parametrize("curve,expected_name", [
    (ec.SECP256R1(), "secp256r1"),
    (ec.SECP384R1(), "secp384r1"),
])
def test_ec_curve_is_identified(curve, expected_name):
    key_pem, cert_pem = _make_ec(curve, hashes.SHA256())

    facts = _scan(cert_pem, key_pem)

    assert not facts.get("error"), facts.get("error")
    assert facts["key_type"] == "EC", f"reported key_type {facts['key_type']!r}"
    assert expected_name in str(facts.get("key_detail") or "").lower(), (
        f"{expected_name} reported key_detail {facts.get('key_detail')!r}"
    )


def test_ed25519_key_is_named_recognisably():
    """Ed25519 must be reported as an algorithm name a consumer can act on.

    scanner._pk_info falls through to the raw class name for anything that is not RSA or EC, so this
    pins whatever it produces to something that still identifies the algorithm — a label like
    "Ed25519PublicKey" carries the algorithm, "UNKNOWN" would not.
    """
    key_pem, cert_pem = _make_ed25519()

    facts = _scan(cert_pem, key_pem)

    assert not facts.get("error"), facts.get("error")
    reported = str(facts.get("key_type") or "")
    assert "ED25519" in reported.upper(), f"Ed25519 certificate reported key_type {reported!r}"


# --------------------------------------------------------------------------------------------
# Signature algorithm
# --------------------------------------------------------------------------------------------

@pytest.mark.parametrize("digest,expected", [
    (hashes.SHA256(), "sha256"),
    (hashes.SHA384(), "sha384"),
])
def test_rsa_signature_digest_is_reported(digest, expected):
    """The signing digest matters on its own: SHA-1 signatures are a finding regardless of key size.

    This failed when written. Certificate parsing was duplicated across the verified and unverified
    code paths and the unverified one never set sig_algorithm, so every certificate that fails
    verification -- self-signed, private CA, expired, hostname mismatch -- reported an empty
    signature algorithm.
    """
    key_pem, cert_pem = _make_rsa(2048, digest)

    facts = _scan(cert_pem, key_pem)

    assert expected in str(facts.get("sig_algorithm") or "").lower(), (
        f"expected {expected} in sig_algorithm, got {facts.get('sig_algorithm')!r}"
    )


def test_sha1_signature_is_visible_on_an_untrusted_certificate():
    """The case the empty sig_algorithm hid.

    A SHA-1 signature is the finding most likely to be sitting on an internal, privately-issued
    certificate -- which is exactly the certificate that fails verification. If the field is blank
    there, no weak-signature rule can fire and the CBOM has no signature algorithm to reference.
    """
    try:
        key_pem, cert_pem = _make_rsa(2048, hashes.SHA1())
    except Exception as exc:  # some builds refuse to sign with SHA-1
        pytest.skip(f"this cryptography build will not mint a SHA-1 certificate: {exc}")

    facts = _scan(cert_pem, key_pem)

    reported = str(facts.get("sig_algorithm") or "").lower()
    assert "sha1" in reported, f"SHA-1 signature reported as {facts.get('sig_algorithm')!r}"


# --------------------------------------------------------------------------------------------
# Negotiated protocol
# --------------------------------------------------------------------------------------------

def test_tls_version_and_cipher_are_reported():
    key_pem, cert_pem = _make_rsa(2048, hashes.SHA256())

    facts = _scan(cert_pem, key_pem, tls_version=ssl.TLSVersion.TLSv1_2)

    assert facts["tls_version"] == "TLSv1.2", f"reported {facts['tls_version']!r}"
    assert facts["cipher_name"], "no cipher suite reported"


def test_tls13_is_reported_when_negotiated():
    key_pem, cert_pem = _make_rsa(2048, hashes.SHA256())

    facts = _scan(cert_pem, key_pem, tls_version=ssl.TLSVersion.TLSv1_3)

    assert facts["tls_version"] == "TLSv1.3", f"reported {facts['tls_version']!r}"


# --------------------------------------------------------------------------------------------
# Certificate identity and validity
# --------------------------------------------------------------------------------------------

def test_subject_and_expiry_are_extracted():
    key_pem, cert_pem = _make_rsa(2048, hashes.SHA256())

    facts = _scan(cert_pem, key_pem)

    assert "rsa2048.test" in str(facts.get("subject") or "").lower(), facts.get("subject")
    assert facts.get("not_after"), "certificate expiry was not extracted"
    days = facts.get("days_until_expiry")
    assert isinstance(days, int) and 300 < days <= 366, f"days_until_expiry={days} for a 365-day cert"


def test_self_signed_certificate_is_still_inspected():
    """Verification fails for a self-signed certificate; the scan must still report its facts.

    A scanner that returns nothing for an untrusted certificate is useless on internal estates, where
    private CAs and self-signed certificates are exactly what needs finding.
    """
    key_pem, cert_pem = _make_rsa(2048, hashes.SHA256())

    facts = _scan(cert_pem, key_pem)

    assert facts["key_type"] == "RSA"
    assert facts.get("verify_error") or facts.get("unverified_fallback"), (
        "a self-signed certificate should be recorded as unverified"
    )


# --------------------------------------------------------------------------------------------
# Risk verdict
# --------------------------------------------------------------------------------------------

def test_classical_endpoint_is_not_reported_as_pqc_ready():
    """Every algorithm here is broken by Shor's algorithm; nothing may be called quantum-safe."""
    key_pem, cert_pem = _make_rsa(2048, hashes.SHA256())

    facts = _scan(cert_pem, key_pem)

    for field in ("pqc_ready", "pqc_safe", "quantum_safe"):
        if field in facts:
            assert not facts[field], f"RSA endpoint reported {field}=True"


def test_unreachable_host_reports_an_error_not_a_clean_result():
    """A failed scan must be distinguishable from a scan that found nothing wrong."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        closed_port = s.getsockname()[1]

    facts = scanner.scan_host("127.0.0.1", closed_port)

    assert facts.get("error"), "connecting to a closed port produced no error"
    assert not facts.get("key_type"), "an unreachable host reported certificate facts"


# --------------------------------------------------------------------------------------------
# Ground-truth matrix
#
# One table over every public-key algorithm the scanner can meet on a TLS endpoint. The
# certificates are minted here, so the expected column is correct by construction rather than by
# opinion, and a new key type cannot be added to the scanner without an answer for every column.
#
# The regression this pins: an Ed25519 certificate used to be reported with key_type
# "Ed25519PublicKey" -- the raw cryptography class name, which matches no algorithm table in the
# product. Every consumer classified it "unknown", and "unknown" reads downstream as *not*
# quantum-vulnerable: the endpoint came out at pqc_relevance LOW, quantum_risk_level "low",
# harvest-now-decrypt-later "unknown", crypto_agility_score 90 and quantum_readiness_level
# "ready_to_track_pqc_rollout". EdDSA over Curve25519 is broken by Shor exactly like ECDSA.
# --------------------------------------------------------------------------------------------

_GROUND_TRUTH = [
    # id,        make,                                              key_type,  bits, curve,       relevance, quantum risk
    ("rsa2048", lambda: _make_rsa(2048, hashes.SHA256()),           "RSA",     2048, "",          "HIGH",   "high"),
    ("rsa3072", lambda: _make_rsa(3072, hashes.SHA256()),           "RSA",     3072, "",          "HIGH",   "high"),
    ("rsa4096", lambda: _make_rsa(4096, hashes.SHA256()),           "RSA",     4096, "",          "HIGH",   "high"),
    ("ec_p256", lambda: _make_ec(ec.SECP256R1(), hashes.SHA256()),  "EC",       256, "secp256r1", "MEDIUM", "medium"),
    ("ec_p384", lambda: _make_ec(ec.SECP384R1(), hashes.SHA384()),  "EC",       384, "secp384r1", "MEDIUM", "medium"),
    ("ec_p521", lambda: _make_ec(ec.SECP521R1(), hashes.SHA512()),  "EC",       521, "secp521r1", "MEDIUM", "medium"),
    ("ed25519", _make_ed25519,                                      "Ed25519",  256, "Ed25519",   "HIGH",   "high"),
]


@pytest.mark.parametrize(
    "case_id,make,key_type,key_bits,curve,pqc_relevance,quantum_risk",
    _GROUND_TRUTH,
    ids=[row[0] for row in _GROUND_TRUTH],
)
def test_ground_truth_matrix(case_id, make, key_type, key_bits, curve, pqc_relevance, quantum_risk):
    key_pem, cert_pem = make()

    facts = _scan(cert_pem, key_pem)

    assert not facts.get("error"), facts.get("error")
    assert facts["scan_status"] == "ok", facts.get("scan_status")
    assert facts["key_type"] == key_type, f"key_type {facts['key_type']!r}"
    assert int(facts["key_bits"]) == key_bits, f"key_bits {facts['key_bits']!r}"
    if curve:
        assert facts["key_curve"] == curve, f"key_curve {facts['key_curve']!r}"

    # Every algorithm in this table is broken by Shor's algorithm. None may be reported as having
    # no classical dependency, and none may score "low" quantum risk.
    assert facts["classical_crypto_dependency"] is True, f"{key_type} reported no classical dependency"
    assert facts["pqc_relevance"] == pqc_relevance, facts["pqc_relevance"]
    assert facts["quantum_risk_level"] == quantum_risk, facts["quantum_risk_level"]
    assert facts["harvest_now_decrypt_later_risk"] in ("high", "critical"), (
        facts["harvest_now_decrypt_later_risk"]
    )
    assert facts["quantum_readiness_level"] != "ready_to_track_pqc_rollout", (
        f"{key_type} endpoint reported ready for PQC rollout"
    )
    # classical_algorithm is the upper-cased key type ("RSA", "EC", "ED25519").
    assert facts["classical_algorithm"] == key_type.upper(), facts["classical_algorithm"]


def test_ed25519_is_quantum_vulnerable_not_unknown():
    """Regression: the exact shape of the bug, asserted alone so the cause is unmistakable."""
    key_pem, cert_pem = _make_ed25519()

    facts = _scan(cert_pem, key_pem)

    assert facts["key_type"] == "Ed25519", facts["key_type"]
    assert facts["classical_crypto_dependency"] is True
    assert facts["pqc_relevance"] != "LOW"
    assert facts["quantum_risk_level"] != "low"
    assert facts["harvest_now_decrypt_later_risk"] != "unknown"
    assert any(f["rule_id"] == "PQC_CLASSICAL_ENDPOINT" for f in facts["findings"]), (
        [f["rule_id"] for f in facts["findings"]]
    )


def test_ec_curve_size_is_reported_numerically():
    """Regression: key_bits is what every downstream risk model reads.

    The scanner only ever produced key_detail -- the modulus size for RSA, a curve *name* for EC --
    and nothing read it. Consumers asked for ``key_bits``, got nothing, and fell back to a hardcoded
    2048/P-256, so an RSA-4096 or P-521 endpoint was scored as the weakest key in its family.
    """
    key_pem, cert_pem = _make_ec(ec.SECP521R1(), hashes.SHA512())

    facts = _scan(cert_pem, key_pem)

    assert facts["key_bits"] == 521, facts["key_bits"]
    assert facts["key_curve"] == "secp521r1", facts["key_curve"]


def test_p521_curve_is_not_read_as_a_tiny_rsa_modulus():
    """Regression: "secp521r1" digit-scanned to 521, which looks like a 521-bit RSA modulus."""
    import policy

    assert policy._rsa_key_size({"key_type": "EC", "key_detail": "secp521r1", "key_bits": 521}) == 0
    assert policy._rsa_key_size({"key_type": "RSA", "key_detail": "3072", "key_bits": 3072}) == 3072


# --------------------------------------------------------------------------------------------
# Edge behaviour: a failed scan must not look like a clean one
# --------------------------------------------------------------------------------------------

def _closed_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _PlaintextServer:
    """A plain TCP server that speaks no TLS at all."""

    def __enter__(self):
        self._stop = threading.Event()
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self._sock.settimeout(0.5)
        self.port = self._sock.getsockname()[1]

        def serve():
            while not self._stop.is_set():
                try:
                    conn, _ = self._sock.accept()
                except (socket.timeout, OSError):
                    continue
                try:
                    conn.settimeout(3)
                    conn.recv(2048)   # let the client send its ClientHello first
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                except OSError:
                    pass
                finally:
                    conn.close()

        self._thread = threading.Thread(target=serve, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=3)


def _assert_failed_scan_is_not_a_clean_one(facts: Dict[str, Any], expected_status: str = "") -> None:
    """The shared contract for every endpoint the scanner could not read.

    Before this, an unreachable host produced three findings about a certificate that was never
    retrieved -- "No CRL distribution points advertised", "No OCSP responder advertised (AIA)" and
    "Certificate chain short or unavailable" -- and came out at quantum_risk_level "low",
    pqc_relevance "LOW" and crypto_agility_score 70. An unreachable host scored *better* than a
    scanned RSA one.
    """
    assert facts.get("error"), "a failed scan reported no error"
    assert facts["scan_status"] != "ok", facts["scan_status"]
    if expected_status:
        assert facts["scan_status"] == expected_status, facts["scan_status"]

    rule_ids = {f["rule_id"] for f in facts["findings"]}
    assert "SCAN_FAILED" in rule_ids, sorted(rule_ids)
    fabricated = {"CERT_NO_CRL_DP", "CERT_NO_OCSP_AIA", "CHAIN_SHORT_OR_UNAVAILABLE",
                  "PQC_RSA_ENDPOINT", "PQC_EC_ENDPOINT", "PQC_CLASSICAL_ENDPOINT"}
    assert not (rule_ids & fabricated), (
        "findings assert certificate facts for an endpoint with no certificate: "
        f"{sorted(rule_ids & fabricated)}"
    )

    # Unknown must never be presented as safe.
    assert facts["quantum_risk_level"] == "unknown", facts["quantum_risk_level"]
    assert facts["pqc_relevance"] == "UNKNOWN", facts["pqc_relevance"]
    assert facts["harvest_now_decrypt_later_risk"] == "unknown", facts["harvest_now_decrypt_later_risk"]
    assert facts["classical_crypto_dependency"] is False
    assert facts["crypto_agility_score"] is None, (
        f"an unscanned endpoint was given a crypto-agility score of {facts['crypto_agility_score']}"
    )
    assert facts["quantum_readiness_level"] == "not_assessed", facts["quantum_readiness_level"]
    statuses = {c["control"]: c["status"] for c in facts["recommended_quantum_safe_controls"]}
    assert statuses.get("Legacy crypto cleanup") == "unknown", statuses
    assert statuses.get("Certificate hygiene") == "unknown", statuses


def test_closed_port_is_reported_as_unknown_not_safe():
    facts = scanner.scan_host("127.0.0.1", _closed_port())
    _assert_failed_scan_is_not_a_clean_one(facts, "unreachable")


def test_non_tls_port_is_reported_as_unknown_not_safe():
    with _PlaintextServer() as server:
        facts = scanner.scan_host("127.0.0.1", server.port)
    # Whether the stack reports a TLS protocol error or an aborted connection depends on the
    # platform; either way the endpoint must come back unknown, never safe.
    _assert_failed_scan_is_not_a_clean_one(facts)
    assert facts["scan_status"] in ("tls_error", "unreachable"), facts["scan_status"]


def test_unresolvable_host_is_reported_as_unknown_not_safe():
    facts = scanner.scan_host("no-such-host.invalid", 443)
    _assert_failed_scan_is_not_a_clean_one(facts)


def test_self_signed_certificate_is_classified_as_untrusted_issuer():
    """Regression: OpenSSL 3.0 renamed the message to "self-signed certificate" (hyphenated).

    The classifier matched only "self signed", so every self-signed endpoint on a modern OpenSSL
    was downgraded from VERIFY_UNTRUSTED_ISSUER to a generic "verification failed".
    """
    err = ssl.SSLCertVerificationError(
        "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate"
    )
    assert scanner._classify_verify_error(err)["verify_reason"] == "untrusted_issuer"
    assert scanner._error_code_from_verify_reason("", "self-signed certificate") == scanner.ERR_SELF_SIGNED


# --------------------------------------------------------------------------------------------
# Negotiated key-exchange group
# --------------------------------------------------------------------------------------------
#
# This is the field that decides whether the product can say anything at all about post-quantum
# key exchange. `ssl.SSLSocket.group()` needs OpenSSL 3.2+ and this runtime links 3.0.18, and even
# on 3.2 the client could not *offer* X25519MLKEM768 (that needs OpenSSL 3.5), so a group observed
# through `ssl` could never be a hybrid one. scanner._probe_key_exchange_group builds the
# ClientHello by hand and reads the ServerHello, which needs no TLS library at all.


class _KeyExchangeServer(_TlsServer):
    """A TLS server restricted to one key-exchange group."""

    def __init__(self, cert_pem, key_pem, curve: str, tls_version=None) -> None:
        super().__init__(cert_pem, key_pem, tls_version)
        self._curve = curve

    def __enter__(self):
        import tempfile

        cert_file = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
        cert_file.write(self._cert_pem)
        cert_file.close()
        key_file = tempfile.NamedTemporaryFile(suffix=".key", delete=False)
        key_file.write(self._key_pem)
        key_file.close()
        self._files = (cert_file.name, key_file.name)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        if self._tls_version is not None:
            context.minimum_version = self._tls_version
            context.maximum_version = self._tls_version
        context.set_ecdh_curve(self._curve)
        context.load_cert_chain(cert_file.name, key_file.name)

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]

        def serve() -> None:
            while not self._stop.is_set():
                try:
                    self._sock.settimeout(0.5)
                    raw, _ = self._sock.accept()
                except (socket.timeout, OSError):
                    continue
                try:
                    with context.wrap_socket(raw, server_side=True) as tls:
                        try:
                            tls.recv(1024)
                            tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                        except OSError:
                            pass
                except (ssl.SSLError, OSError):
                    pass

        self._thread = threading.Thread(target=serve, daemon=True)
        self._thread.start()
        return self


@pytest.mark.parametrize("curve,expected,tls_version", [
    ("X25519", "x25519", ssl.TLSVersion.TLSv1_3),
    # The server prefers a group we sent no key share for, so it answers with a
    # HelloRetryRequest. That is exactly the shape of the reply a PQC-enabled server gives, so
    # covering it here is what makes the hybrid case reachable.
    ("secp384r1", "secp384r1", ssl.TLSVersion.TLSv1_3),
    ("secp521r1", "secp521r1", ssl.TLSVersion.TLSv1_2),
])
def test_negotiated_key_exchange_group_is_observed(curve, expected, tls_version):
    """Regression: the scanner recorded nothing at all about the key exchange.

    `scan_host()` had no negotiated_group / key_exchange field, so the CBOM's key-exchange
    algorithm was always absent, the trust passport's hybrid observation count was structurally
    zero, and HNDL's pqc_hybrid and pqc_pure buckets could never be reached from a TLS scan.
    """
    key_pem, cert_pem = _make_rsa(2048, hashes.SHA256())
    with _KeyExchangeServer(cert_pem, key_pem, curve, tls_version) as server:
        facts = scanner.scan_host("127.0.0.1", server.port)

    assert facts["key_exchange_observed"] is True, facts["key_exchange_unobservable_reason"]
    assert facts["key_exchange"] == expected, facts["key_exchange"]
    assert facts["key_exchange_family"] == "classical", facts["key_exchange_family"]


class _HybridServerHello:
    """A server that answers one ClientHello with a HelloRetryRequest naming X25519MLKEM768.

    No TLS stack available here can perform hybrid post-quantum key exchange -- OpenSSL 3.0.18
    does not implement it -- so the only way to prove the scanner *recognises* the group is to
    hand it the bytes a server that does implement it would send. The reply is a real, spec-shaped
    HelloRetryRequest; only the handshake that would follow it is absent, and the probe never gets
    that far.
    """

    HRR_RANDOM = bytes.fromhex(
        "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
    )
    GROUP = 0x11EC  # X25519MLKEM768

    def __init__(self) -> None:
        self.port = 0
        self._sock = None
        self._thread = None
        self._stop = threading.Event()

    def _hello_retry_request(self, session_id: bytes) -> bytes:
        import struct

        def u16(v):
            return struct.pack(">H", v)

        exts = u16(0x002B) + u16(2) + u16(0x0304)           # supported_versions: TLS 1.3
        exts += u16(0x0033) + u16(2) + u16(self.GROUP)      # key_share: selected group only
        body = (u16(0x0303) + self.HRR_RANDOM
                + bytes([len(session_id)]) + session_id
                + u16(0x1301) + b"\x00"
                + u16(len(exts)) + exts)
        handshake = b"\x02" + len(body).to_bytes(3, "big") + body
        return b"\x16\x03\x03" + u16(len(handshake)) + handshake

    def __enter__(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]

        def serve() -> None:
            while not self._stop.is_set():
                try:
                    self._sock.settimeout(0.5)
                    raw, _ = self._sock.accept()
                except (socket.timeout, OSError):
                    continue
                try:
                    data = raw.recv(8192)
                    # Echo the client's legacy_session_id back, as RFC 8446 requires.
                    session_id = b""
                    offset = 5 + 4 + 2 + 32
                    if len(data) > offset:
                        sid_len = data[offset]
                        session_id = data[offset + 1:offset + 1 + sid_len]
                    raw.sendall(self._hello_retry_request(session_id))
                except OSError:
                    pass
                finally:
                    try:
                        raw.close()
                    except OSError:
                        pass

        self._thread = threading.Thread(target=serve, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        if self._thread:
            self._thread.join(timeout=3)


def test_hybrid_post_quantum_key_exchange_is_recognised():
    """X25519MLKEM768 must be observed as hybrid, not as plain X25519 and not as unknown."""
    with _HybridServerHello() as server:
        result = scanner._probe_key_exchange_group("127.0.0.1", server.port)

    assert result["key_exchange_observed"] is True, result["key_exchange_unobservable_reason"]
    assert result["key_exchange"] == "X25519MLKEM768", result["key_exchange"]
    assert result["key_exchange_group_id"] == 0x11EC
    assert result["key_exchange_family"] == "pqc_hybrid", result["key_exchange_family"]
    assert result["key_exchange_hello_retry"] is True


@pytest.mark.parametrize("name,expected", [
    ("X25519MLKEM768", "pqc_hybrid"),
    ("SecP256r1MLKEM768", "pqc_hybrid"),
    ("X25519Kyber768Draft00", "pqc_hybrid"),
    ("MLKEM768", "pqc_pure"),
    ("x25519", "classical"),
    ("secp384r1", "classical"),
    ("", ""),
])
def test_key_exchange_group_families(name, expected):
    assert scanner.classify_key_exchange_group(name) == expected


def test_unreachable_endpoint_reports_key_exchange_as_unobserved_not_absent():
    """"Not observed" and "no post-quantum key exchange" are different claims.

    A field that reports zero hybrid observations for an endpoint nobody could reach asserts a
    measurement that was never taken, so the scanner states the reason instead.
    """
    facts = scanner.scan_host("127.0.0.1", _closed_port())

    assert facts["key_exchange"] == ""
    assert facts["key_exchange_observed"] is False
    assert facts["key_exchange_family"] == ""
    assert facts["key_exchange_unobservable_reason"], "no reason given for the missing observation"


def test_non_tls_endpoint_reports_key_exchange_as_unobserved():
    with _PlaintextServer() as server:
        facts = scanner.scan_host("127.0.0.1", server.port)

    assert facts["key_exchange_observed"] is False
    assert facts["key_exchange_unobservable_reason"]
