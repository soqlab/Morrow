"""Known-answer tests for the HashiCorp Vault secret scanner.

services.secrets_scanner.scan_vault had no coverage because it needs a Vault
instance. It does not need a real one -- it speaks the Vault v1 HTTP API over
plain urllib, so a local HTTP server returning Vault-shaped JSON exercises the
whole path: token header, KV listing, recursion into nested paths, KV v2
unwrapping, PEM classification, the field-name heuristic, PKI CA inspection, and
the 403/404 handling that decides whether a partial scan is reported as an error.

Keys are generated for real rather than hard-coded, because the PEM classifier
estimates key size from DER byte length -- a synthetic blob of the wrong length
would test the heuristic against a fiction.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from services.secrets_scanner import scan_vault

TOKEN = "s.test-token"


def _pem(key):
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()


RSA_2048_PEM = _pem(rsa.generate_private_key(public_exponent=65537, key_size=2048))
EC_P256_PEM = _pem(ec.generate_private_key(ec.SECP256R1()))


class _VaultHandler(BaseHTTPRequestHandler):
    routes: dict = {}
    seen_tokens: list = []

    def log_message(self, *args):
        pass

    def do_GET(self):
        type(self).seen_tokens.append(self.headers.get("X-Vault-Token"))
        payload = self.routes.get(self.path)
        if payload is None:
            self.send_error(404)
            return
        if payload == "__forbidden__":
            self.send_error(403)
            return
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _VaultServer:
    def __init__(self, routes):
        handler = type("_H", (_VaultHandler,), {"routes": routes, "seen_tokens": []})
        self.handler = handler
        self.httpd = HTTPServer(("127.0.0.1", 0), handler)
        self.addr = f"http://127.0.0.1:{self.httpd.server_port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)
        return False


def test_vault_kv_scan_classifies_keys_and_recurses_into_subpaths():
    routes = {
        "/v1/secret/?list=true": {"data": {"keys": ["db-cert", "nested/"]}},
        "/v1/secret/db-cert": {"data": {"tls_cert_key": RSA_2048_PEM}},
        "/v1/secret/nested/?list=true": {"data": {"keys": ["ec-key"]}},
        "/v1/secret/nested/ec-key": {"data": {"leaf": EC_P256_PEM}},
    }
    with _VaultServer(routes) as server:
        result = scan_vault(server.addr, TOKEN, mount_paths=["secret/"])
        tokens = server.handler.seen_tokens

    # The token must actually be sent; a scan that silently ran unauthenticated
    # would return an empty, reassuring result.
    assert tokens and all(t == TOKEN for t in tokens)

    findings = result["findings"]
    by_path = {f["path"]: f for f in findings}

    assert "vault://secret/db-cert" in by_path, "top-level secret was not scanned"
    assert "vault://secret/nested/ec-key" in by_path, "did not recurse into nested/"

    rsa_finding = by_path["vault://secret/db-cert"]
    assert rsa_finding["key_type"] == "RSA"
    assert rsa_finding["key_bits"] == 2048
    assert rsa_finding["key_kind"] == "private"
    assert rsa_finding["quantum_vulnerable"] is True
    assert rsa_finding["source"] == "vault"

    ec_finding = by_path["vault://secret/nested/ec-key"]
    assert ec_finding["key_type"] == "EC"
    assert ec_finding["key_bits"] == 256
    assert ec_finding["quantum_vulnerable"] is True

    # Fingerprints must not be the key material itself.
    for finding in findings:
        assert "BEGIN" not in finding["fingerprint"]


def test_kv_v2_envelope_is_unwrapped():
    """KV v2 nests the payload under data.data; without unwrapping, the scanner
    sees one non-string value and reports a clean vault."""
    routes = {
        "/v1/kv/?list=true": {"data": {"keys": ["app"]}},
        "/v1/kv/app": {"data": {"data": {"signing_pem": RSA_2048_PEM},
                                "metadata": {"version": 3}}},
    }
    with _VaultServer(routes) as server:
        result = scan_vault(server.addr, TOKEN, mount_paths=["kv/"])

    assert len(result["findings"]) == 1
    assert result["findings"][0]["key_type"] == "RSA"
    assert result["findings"][0]["field"] == "signing_pem"


def test_suggestive_field_names_are_flagged_for_review_not_asserted_as_vulnerable():
    routes = {
        "/v1/secret/?list=true": {"data": {"keys": ["app"]}},
        "/v1/secret/app": {"data": {
            "jwt_secret": "not-a-pem-just-a-string",
            "hostname": "db.internal",
        }},
    }
    with _VaultServer(routes) as server:
        result = scan_vault(server.addr, TOKEN, mount_paths=["secret/"])

    findings = result["findings"]
    assert len(findings) == 1, "only the suggestive field should be flagged"
    flagged = findings[0]
    assert flagged["field"] == "jwt_secret"
    # A heuristic name match is not evidence of a quantum-vulnerable key, and
    # must not be reported as one.
    assert flagged["quantum_vulnerable"] is None
    assert flagged["risk_level"] == "unknown"
    assert "manual review" in flagged["reason"].lower()


def test_pki_mount_ca_certificate_is_inspected():
    routes = {
        "/v1/secret/?list=true": {"data": {"keys": []}},
        "/v1/pki/cert/ca": {"data": {"certificate": RSA_2048_PEM}},
    }
    with _VaultServer(routes) as server:
        result = scan_vault(server.addr, TOKEN, mount_paths=["secret/"], pki_mounts=["pki/"])

    ca = [f for f in result["findings"] if f["source"] == "vault_pki"]
    assert len(ca) == 1
    assert ca[0]["key_kind"] == "ca"
    assert ca[0]["path"] == "vault://pki/cert/ca"


def test_denied_paths_are_skipped_quietly_but_real_errors_are_reported():
    """403/404 are normal for a least-privilege Vault token and must not be
    reported as scan errors; anything else must be."""
    routes = {
        "/v1/secret/?list=true": {"data": {"keys": ["readable", "denied"]}},
        "/v1/secret/readable": {"data": {"tls_key": RSA_2048_PEM}},
        "/v1/secret/denied": "__forbidden__",
    }
    with _VaultServer(routes) as server:
        result = scan_vault(server.addr, TOKEN, mount_paths=["secret/"])

    assert len(result["findings"]) == 1
    assert not result["errors"], f"403 should not surface as an error: {result['errors']}"


def test_unreachable_vault_reports_an_error_rather_than_an_empty_clean_result():
    result = scan_vault("http://127.0.0.1:1", TOKEN, mount_paths=["secret/"])

    assert result["findings"] == []
    assert result["errors"], "an unreachable Vault must not look like a clean one"
