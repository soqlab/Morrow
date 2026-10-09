"""Known-answer tests for the Azure Key Vault scanner.

services.secrets_scanner.scan_azure_key_vault was the last scanner entry point
with no coverage. It speaks plain HTTP -- an OAuth2 client-credentials token
exchange, then the Key Vault REST API -- so a local HTTP server exercises the
real request/parse/classify path.

The only thing faked is DNS: the token endpoint hostname is hardcoded to
login.microsoftonline.com, so urlopen is wrapped to send that one prefix to the
local server. Everything else -- the form encoding, the bearer header, the JSON
parsing, the classification -- is the real code doing real HTTP.

What is easy to get silently wrong here:

  * RSA key size is inferred from the base64url modulus when Key Vault omits
    key_size. Get the decode wrong and every RSA key is reported at the 2048
    fallback, so a weak 1024-bit key is scored as if it were fine.
  * HSM-backed keys arrive as "RSA-HSM"/"EC-HSM". Unmapped, they fall through to
    a raw kty string that _assess_key cannot judge -- an HSM key silently
    becomes "unknown" instead of a finding.
  * A failed token exchange must produce an error, not an empty clean report.
"""

import base64
import json
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from services import secrets_scanner
from services.secrets_scanner import scan_azure_key_vault

TENANT = "tenant-123"
CLIENT_ID = "client-123"
CLIENT_SECRET = "secret-123"
LOGIN_PREFIX = "https://login.microsoftonline.com"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _modulus(bits: int) -> str:
    """A base64url modulus of the byte length Key Vault would return."""
    return _b64url(b"\xab" * (bits // 8))


class _AzureHandler(BaseHTTPRequestHandler):
    routes: dict = {}
    token_status: int = 200
    seen: list = []

    def log_message(self, *args):
        pass

    def do_POST(self):
        # The OAuth2 token exchange.
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode()
        type(self).seen.append(("token", body))
        if self.token_status != 200:
            self.send_error(self.token_status)
            return
        self._json({"access_token": "test-token", "token_type": "Bearer"})

    def do_GET(self):
        type(self).seen.append(("get", self.path, self.headers.get("Authorization")))
        # Strip the api-version query the scanner appends.
        path = self.path.split("?")[0].lstrip("/")
        payload = self.routes.get(path)
        if payload is None:
            self.send_error(404)
            return
        if payload == "__forbidden__":
            self.send_error(403)
            return
        if payload == "__server_error__":
            self.send_error(500)
            return
        self._json(payload)

    def _json(self, obj):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _AzureServer:
    def __init__(self, routes, token_status=200):
        handler = type("_H", (_AzureHandler,), {
            "routes": routes, "token_status": token_status, "seen": [],
        })
        self.handler = handler
        self.httpd = HTTPServer(("127.0.0.1", 0), handler)
        self.base = f"http://127.0.0.1:{self.httpd.server_port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)
        return False


@pytest.fixture()
def azure(monkeypatch):
    """Redirect only the hardcoded login.microsoftonline.com host to the test server."""
    real_urlopen = urllib.request.urlopen

    def _make(server):
        def _patched(req, *args, **kwargs):
            url = req.full_url if hasattr(req, "full_url") else str(req)
            if url.startswith(LOGIN_PREFIX):
                new = urllib.request.Request(
                    server.base + "/token",
                    data=req.data,
                    headers=dict(req.header_items()),
                    method="POST",
                )
                return real_urlopen(new, *args, **kwargs)
            return real_urlopen(req, *args, **kwargs)
        monkeypatch.setattr(secrets_scanner.urllib.request, "urlopen", _patched)
    return _make


def _scan(server):
    return scan_azure_key_vault(server.base, TENANT, CLIENT_ID, CLIENT_SECRET)


def test_rsa_and_ec_keys_are_classified_with_sizes(azure):
    routes = {
        "keys": {"value": [
            {"kid": "https://v.vault.azure.net/keys/tls-rsa"},
            {"kid": "https://v.vault.azure.net/keys/sig-ec"},
        ]},
        "keys/tls-rsa": {"key": {"kty": "RSA", "key_size": 2048, "n": _modulus(2048)}},
        "keys/sig-ec": {"key": {"kty": "EC", "crv": "P-256"}},
        "certificates": {"value": []},
    }
    with _AzureServer(routes) as server:
        azure(server)
        result = _scan(server)

    assert not result["errors"], result["errors"]
    by_path = {f["path"]: f for f in result["findings"]}
    assert set(by_path) == {"akv://keys/tls-rsa", "akv://keys/sig-ec"}

    rsa = by_path["akv://keys/tls-rsa"]
    assert rsa["key_type"] == "RSA"
    assert rsa["key_bits"] == 2048
    assert rsa["quantum_vulnerable"] is True
    assert rsa["source"] == "azure_key_vault"

    ec = by_path["akv://keys/sig-ec"]
    assert ec["key_type"] == "EC"
    assert ec["quantum_vulnerable"] is True


def test_rsa_size_is_inferred_from_the_modulus_when_key_size_is_absent(azure):
    """Key Vault omits key_size on some responses. A 1024-bit key that silently
    falls back to the 2048 default is scored as materially safer than it is."""
    routes = {
        "keys": {"value": [
            {"kid": "https://v.vault.azure.net/keys/weak"},
            {"kid": "https://v.vault.azure.net/keys/strong"},
        ]},
        "keys/weak": {"key": {"kty": "RSA", "n": _modulus(1024)}},
        "keys/strong": {"key": {"kty": "RSA", "n": _modulus(4096)}},
        "certificates": {"value": []},
    }
    with _AzureServer(routes) as server:
        azure(server)
        result = _scan(server)

    by_path = {f["path"]: f for f in result["findings"]}
    assert by_path["akv://keys/weak"]["key_bits"] == 1024, "modulus length was not used"
    assert by_path["akv://keys/strong"]["key_bits"] == 4096


def test_hsm_backed_keys_are_mapped_to_their_algorithm(azure):
    """RSA-HSM / EC-HSM must resolve to RSA / EC. Left unmapped they reach
    _assess_key as an unknown identifier and are reported "unknown" -- an HSM
    key quietly dropping out of the vulnerable set."""
    routes = {
        "keys": {"value": [
            {"kid": "https://v.vault.azure.net/keys/hsm-rsa"},
            {"kid": "https://v.vault.azure.net/keys/hsm-ec"},
        ]},
        "keys/hsm-rsa": {"key": {"kty": "RSA-HSM", "key_size": 3072, "n": _modulus(3072)}},
        "keys/hsm-ec": {"key": {"kty": "EC-HSM", "crv": "P-384"}},
        "certificates": {"value": []},
    }
    with _AzureServer(routes) as server:
        azure(server)
        result = _scan(server)

    by_path = {f["path"]: f for f in result["findings"]}
    assert by_path["akv://keys/hsm-rsa"]["key_type"] == "RSA"
    assert by_path["akv://keys/hsm-rsa"]["quantum_vulnerable"] is True
    assert by_path["akv://keys/hsm-ec"]["key_type"] == "EC"
    assert by_path["akv://keys/hsm-ec"]["quantum_vulnerable"] is True


def test_certificates_are_read_from_their_policy(azure):
    routes = {
        "keys": {"value": []},
        "certificates": {"value": [{"id": "https://v.vault.azure.net/certificates/tls-cert"}]},
        "certificates/tls-cert": {
            "policy": {"key_props": {"kty": "RSA", "key_size": 4096}}
        },
    }
    with _AzureServer(routes) as server:
        azure(server)
        result = _scan(server)

    certs = [f for f in result["findings"] if f["field"] == "certificate"]
    assert len(certs) == 1
    assert certs[0]["path"] == "akv://certificates/tls-cert"
    assert certs[0]["key_type"] == "RSA"
    assert certs[0]["key_bits"] == 4096
    assert certs[0]["key_kind"] == "cert"


def test_bearer_token_is_obtained_and_sent_on_every_request(azure):
    routes = {
        "keys": {"value": [{"kid": "https://v.vault.azure.net/keys/k1"}]},
        "keys/k1": {"key": {"kty": "RSA", "key_size": 2048, "n": _modulus(2048)}},
        "certificates": {"value": []},
    }
    with _AzureServer(routes) as server:
        azure(server)
        _scan(server)
        seen = server.handler.seen

    token_calls = [s for s in seen if s[0] == "token"]
    assert len(token_calls) == 1, "the token should be fetched once, not per request"
    assert "grant_type=client_credentials" in token_calls[0][1]
    assert CLIENT_ID in token_calls[0][1]

    gets = [s for s in seen if s[0] == "get"]
    assert gets, "no vault requests were made"
    assert all(s[2] == "Bearer test-token" for s in gets), "a request went out unauthenticated"


def test_a_failed_token_exchange_reports_an_error_and_scans_nothing(azure):
    routes = {"keys": {"value": [{"kid": "https://v.vault.azure.net/keys/k1"}]}}
    with _AzureServer(routes, token_status=401) as server:
        azure(server)
        result = _scan(server)

    assert result["findings"] == []
    assert result["errors"], "a vault we could not authenticate to is not a clean vault"
    assert any("token" in e.lower() for e in result["errors"])
    # It must not have gone on to request vault contents with no token.
    assert not [s for s in server.handler.seen if s[0] == "get"]


def test_denied_paths_are_skipped_quietly_but_server_errors_are_reported(azure):
    """403/404 are normal for a scoped service principal; a 500 is not."""
    quiet = {"keys": "__forbidden__", "certificates": {"value": []}}
    with _AzureServer(quiet) as server:
        azure(server)
        result = _scan(server)
    assert not result["errors"], f"403 must not be an error: {result['errors']}"

    loud = {"keys": "__server_error__", "certificates": {"value": []}}
    with _AzureServer(loud) as server:
        azure(server)
        result = _scan(server)
    assert result["errors"], "a 500 must be surfaced"


def test_an_empty_vault_is_clean_without_errors(azure):
    routes = {"keys": {"value": []}, "certificates": {"value": []}}
    with _AzureServer(routes) as server:
        azure(server)
        result = _scan(server)

    assert result["findings"] == []
    assert not result["errors"]
