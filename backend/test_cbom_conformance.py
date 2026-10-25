"""Every CBOM this tool exports must validate against the official CycloneDX 1.6 schema.

A CBOM exists so that someone else's pipeline can read it. When the generator emitted
`executionEnvironment: "software"`, `implementationPlatform: "TLS"`, `primitive: "cipher"` and
`publicKeyRef` (the real field is `subjectPublicKeyRef`), every export was rejected on import by any
conforming consumer -- Dependency-Track, an OWASP toolchain, a procurement reviewer's validator --
while the module advertised itself as standards-compliant. Nothing in the product noticed, because
nothing validated the output.

The schema is vendored under schemas/cyclonedx/ so this runs offline and in CI. Refresh it from
https://github.com/CycloneDX/specification/tree/master/schema when moving to a new spec version.
"""
from __future__ import annotations

import json
import pathlib

import pytest

from services.cbom import (
    algorithms_in_cipher_suite,
    canonical_algorithm,
    generate_cbom,
    signature_algorithm_parts,
)

SCHEMA_DIR = pathlib.Path(__file__).resolve().parent / "schemas" / "cyclonedx"


def _validator():
    jsonschema = pytest.importorskip("jsonschema", reason="jsonschema is required to check CBOM conformance")
    schema = json.loads((SCHEMA_DIR / "bom-1.6.schema.json").read_text(encoding="utf-8"))
    # The spec's $refs point at absolute cyclonedx.org URLs; map them to the vendored copies so no
    # network access is needed.
    store = {
        "http://cyclonedx.org/schema/spdx.SNAPSHOT.schema.json":
            json.loads((SCHEMA_DIR / "spdx.schema.json").read_text(encoding="utf-8")),
        "http://cyclonedx.org/schema/jsf-0.82.SNAPSHOT.schema.json":
            json.loads((SCHEMA_DIR / "jsf-0.82.schema.json").read_text(encoding="utf-8")),
    }
    resolver = jsonschema.RefResolver.from_schema(schema, store=store)
    return jsonschema.Draft7Validator(schema, resolver=resolver)


def _assert_valid(document):
    validator = _validator()
    errors = sorted(validator.iter_errors(document), key=lambda e: list(e.absolute_path))
    if errors:
        detail = "\n".join(
            f"  {'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message[:200]}"
            for e in errors[:20]
        )
        raise AssertionError(f"CBOM violates CycloneDX 1.6 ({len(errors)} error(s)):\n{detail}")


TLS13_RSA_ENDPOINT = {
    "host": "example.com", "port": 443,
    "tls_version": "TLSv1.3", "cipher_name": "TLS_AES_256_GCM_SHA384",
    "cert_subject": "CN=example.com", "cert_issuer": "CN=Example CA",
    "cert_not_before": "2026-01-01T00:00:00Z", "cert_not_after": "2027-01-01T00:00:00Z",
    "cert_sig_alg": "sha256WithRSAEncryption", "cert_key_type": "RSA", "cert_key_bits": 2048,
    "key_exchange": "ECDHE", "signature_algorithm": "RSA",
    "pq_ready": False, "risk_level": "high",
    "findings": [{"rule_id": "MORROW_RSA_ENDPOINT", "severity": "high",
                  "title": "RSA key exchange is quantum-vulnerable",
                  "fix": "Migrate to an ML-KEM hybrid group"}],
}

LEGACY_ENDPOINT = {
    "host": "legacy.internal", "port": 8443,
    "tls_version": "TLSv1.0", "cipher_name": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "cert_subject": "CN=legacy.internal", "cert_issuer": "CN=Old CA",
    "cert_sig_alg": "sha1WithRSAEncryption", "cert_key_type": "RSA", "cert_key_bits": 1024,
    "key_exchange": "RSA", "signature_algorithm": "RSA",
    "findings": [{"rule_id": "TLS_VERSION_TOO_LOW", "severity": "critical", "title": "TLS 1.0"}],
}

MORROW_ENDPOINT = {
    "host": "morrow.example.com", "port": 443,
    "tls_version": "TLSv1.3", "cipher_name": "TLS_CHACHA20_POLY1305_SHA256",
    "cert_subject": "CN=morrow.example.com", "cert_issuer": "CN=post-quantum CA",
    "cert_sig_alg": "ML-DSA-65", "cert_key_type": "ML-DSA-65",
    "key_exchange": "X25519", "signature_algorithm": "ML-DSA-65",
    "findings": [],
}


def test_empty_cbom_is_valid():
    """An estate with nothing scanned yet must still export a valid document."""
    _assert_valid(generate_cbom([], org_name="Acme", scan_id="empty"))


def test_typical_tls_endpoint_cbom_is_valid():
    _assert_valid(generate_cbom([TLS13_RSA_ENDPOINT], org_name="Acme Corp", scan_id="scan-1"))


def test_mixed_estate_cbom_is_valid():
    _assert_valid(generate_cbom(
        [TLS13_RSA_ENDPOINT, LEGACY_ENDPOINT, MORROW_ENDPOINT], org_name="Acme Corp", scan_id="scan-2"
    ))


def test_results_with_errors_and_missing_fields_are_valid():
    """Scanner output is not uniform: unreachable hosts and partial results must not break export."""
    _assert_valid(generate_cbom([
        {"host": "down.example.com", "port": 443, "error": "connection refused"},
        {"host": "bare.example.com", "port": 443},
        {},
    ], org_name="Acme"))


def test_repeated_results_for_one_endpoint_produce_one_component():
    """Scan history contains many rows per endpoint, and refs are content-derived.

    Without deduplication the same bom-ref is emitted repeatedly, and CycloneDX requires bom-refs to
    be unique — so an organization-wide export (which reads history) produced a document that failed
    validation, while a single synthetic result passed. This is the case only real data exposed.
    """
    history = [dict(TLS13_RSA_ENDPOINT) for _ in range(5)]

    doc = generate_cbom(history, org_name="Acme")

    refs = [c["bom-ref"] for c in doc["components"]]
    assert len(refs) == len(set(refs)), f"duplicate component bom-refs: {refs}"
    dep_refs = [d["ref"] for d in doc["dependencies"]]
    assert len(dep_refs) == len(set(dep_refs)), f"duplicate dependency refs: {dep_refs}"
    _assert_valid(doc)


def test_every_reference_resolves_to_a_component_in_the_bom():
    """refType fields and dependencies must point at real bom-refs.

    A dangling reference validates against the schema — refType is just a string — but breaks any
    consumer that resolves the graph, which is the reason to emit references at all.
    """
    doc = generate_cbom([TLS13_RSA_ENDPOINT, LEGACY_ENDPOINT, MORROW_ENDPOINT], org_name="Acme")
    known = {c["bom-ref"] for c in doc["components"]}
    known.add(doc["metadata"]["component"]["bom-ref"])

    dangling = []
    for component in doc["components"]:
        crypto = component.get("cryptoProperties") or {}
        cert = crypto.get("certificateProperties") or {}
        for field in ("signatureAlgorithmRef", "subjectPublicKeyRef"):
            ref = cert.get(field)
            if ref and ref not in known:
                dangling.append(f"{component['bom-ref']}.{field} -> {ref}")
        proto = crypto.get("protocolProperties") or {}
        for ref in proto.get("cryptoRefArray") or []:
            if ref not in known:
                dangling.append(f"{component['bom-ref']}.cryptoRefArray -> {ref}")
        for suite in proto.get("cipherSuites") or []:
            for ref in suite.get("algorithms") or []:
                if ref not in known:
                    dangling.append(f"{component['bom-ref']}.cipherSuites -> {ref}")

    for dep in doc.get("dependencies") or []:
        if dep["ref"] not in known:
            dangling.append(f"dependencies.ref -> {dep['ref']}")
        for ref in dep.get("dependsOn") or []:
            if ref not in known:
                dangling.append(f"dependencies[{dep['ref']}].dependsOn -> {ref}")

    for vuln in doc.get("vulnerabilities") or []:
        for affected in vuln.get("affects") or []:
            if affected.get("ref") not in known:
                dangling.append(f"vulnerability {vuln.get('id')}.affects -> {affected.get('ref')}")

    assert not dangling, "references that resolve to nothing in the BOM:\n  " + "\n  ".join(dangling)


def test_certificate_links_to_its_signing_and_public_key_algorithms():
    doc = generate_cbom([TLS13_RSA_ENDPOINT], org_name="Acme")
    certs = [c for c in doc["components"]
             if (c.get("cryptoProperties") or {}).get("assetType") == "certificate"]
    assert certs, "no certificate component was emitted"
    props = certs[0]["cryptoProperties"]["certificateProperties"]
    # sha256WithRSAEncryption decomposes into an RSA signer and a SHA-256 digest.
    assert props["signatureAlgorithmRef"] == "alg:rsa-2048"
    assert props["subjectPublicKeyRef"] == "alg:rsa-2048"
    names = {c["name"] for c in doc["components"]}
    assert "SHA-256" in names, "the digest named in the signature algorithm was not emitted"


def test_cipher_suite_is_decomposed_into_algorithms():
    doc = generate_cbom([TLS13_RSA_ENDPOINT], org_name="Acme")
    names = {c["name"] for c in doc["components"]}
    assert "AES-256-GCM" in names
    assert "SHA-384" in names
    assert "ECDHE" in names


def test_bom_refs_are_stable_across_exports():
    """Two exports of an unchanged estate should differ only by serialNumber and timestamp."""
    a = generate_cbom([TLS13_RSA_ENDPOINT], org_name="Acme", scan_id="s1")
    b = generate_cbom([TLS13_RSA_ENDPOINT], org_name="Acme", scan_id="s1")

    assert [c["bom-ref"] for c in a["components"]] == [c["bom-ref"] for c in b["components"]]
    assert a["serialNumber"] != b["serialNumber"], "serialNumber must be unique per BOM"


@pytest.mark.parametrize("name,bits,expected", [
    ("RSA", 2048, "RSA-2048"),
    ("RSA", 4096, "RSA-4096"),
    ("rsaEncryption", 3072, "RSA-3072"),
    ("secp384r1", 0, "ECDSA-P384"),
    ("prime256v1", 0, "ECDSA-P256"),
    ("id-ecPublicKey", 521, "ECDSA-P521"),
    ("X25519", 0, "X25519"),
    ("ECDHE", 0, "ECDHE"),
    ("ML-KEM-1024", 0, "ML-KEM-1024"),
    ("Kyber768", 0, "ML-KEM-768"),
    ("Dilithium3", 0, "ML-DSA-65"),
    ("AES_256_GCM", 0, "AES-256-GCM"),
    ("3DES", 0, "3DES"),
    ("totally unknown thing", 0, None),
])
def test_algorithm_names_resolve(name, bits, expected):
    assert canonical_algorithm(name, bits) == expected


@pytest.mark.parametrize("suite,expected", [
    ("TLS_AES_256_GCM_SHA384", {"AES-256-GCM", "SHA-384"}),
    ("TLS_CHACHA20_POLY1305_SHA256", {"CHACHA20-POLY1305", "SHA-256"}),
    ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", {"AES-128-GCM", "SHA-256", "ECDHE", "RSA-2048"}),
    ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", {"3DES", "SHA-1", "RSA-2048"}),
    ("", set()),
])
def test_cipher_suite_decomposition(suite, expected):
    assert set(algorithms_in_cipher_suite(suite)) == expected


@pytest.mark.parametrize("sig,expected", [
    ("sha256WithRSAEncryption", ("RSA-2048", "SHA-256")),
    ("ecdsa-with-SHA384", ("ECDSA-P384", "SHA-384")),
    ("Ed25519", ("Ed25519", None)),
    ("ML-DSA-65", ("ML-DSA-65", None)),
])
def test_signature_algorithm_decomposition(sig, expected):
    assert signature_algorithm_parts(sig) == expected


def test_quantum_vulnerable_algorithms_report_nist_level_zero():
    """RSA and elliptic-curve algorithms are broken by Shor's algorithm at any key size."""
    doc = generate_cbom([TLS13_RSA_ENDPOINT, LEGACY_ENDPOINT], org_name="Acme")
    levels = {
        c["name"]: c["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"]
        for c in doc["components"]
        if (c.get("cryptoProperties") or {}).get("assetType") == "algorithm"
    }
    for name in ("RSA-2048", "ECDHE"):
        assert levels.get(name) == 0, f"{name} should report no post-quantum security"


def test_post_quantum_algorithms_report_their_nist_category():
    doc = generate_cbom([MORROW_ENDPOINT], org_name="Acme")
    levels = {
        c["name"]: c["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"]
        for c in doc["components"]
        if (c.get("cryptoProperties") or {}).get("assetType") == "algorithm"
    }
    assert levels.get("ML-DSA-65") == 3, "ML-DSA-65 is NIST category 3"
