"""Regressions for scanner bugs found by the public-endpoint accuracy suite (docs/ACCURACY.md).

Each bug was found by disagreeing with an OpenSSL/OpenSSH reference on a real public host. The
tests below never touch that host: each one reproduces the server behaviour on loopback, either
with a local TLS server configured the same way or by replaying the bytes the public server sent.
"""
from __future__ import annotations

import datetime
import os
import socket
import ssl
import tempfile
import threading
import warnings
from typing import Any

import pytest

pytest.importorskip("cryptography")

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import scanner


def _rsa_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    return cert.public_bytes(serialization.Encoding.PEM), key_pem


class _Server:
    """Loopback TLS server pinned to one protocol version and cipher string."""

    def __init__(self, version: ssl.TLSVersion, ciphers: str) -> None:
        self.version, self.ciphers = version, ciphers
        self.port = 0
        self._stop = threading.Event()

    def __enter__(self) -> "_Server":
        cert_pem, key_pem = _rsa_cert()
        d = tempfile.mkdtemp()
        self._cert, self._key = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
        with open(self._cert, "wb") as fh:
            fh.write(cert_pem)
        with open(self._key, "wb") as fh:
            fh.write(key_pem)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            with warnings.catch_warnings():     # TLS 1.0/1.1 are deprecated; serving them is the point
                warnings.simplefilter("ignore", DeprecationWarning)
                ctx.minimum_version = self.version
                ctx.maximum_version = self.version
            ctx.set_ciphers(self.ciphers)
            ctx.load_cert_chain(self._cert, self._key)
        except (ssl.SSLError, ValueError) as exc:
            pytest.skip(f"this OpenSSL build cannot serve {self.version.name}: {exc}")
        self._ctx = ctx
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self._sock.settimeout(0.5)
        self.port = self._sock.getsockname()[1]
        self._t = threading.Thread(target=self._serve, daemon=True)
        self._t.start()
        return self

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                raw, _ = self._sock.accept()
            except (socket.timeout, OSError):
                continue
            try:
                with self._ctx.wrap_socket(raw, server_side=True) as tls:
                    tls.settimeout(2)
                    try:
                        tls.recv(64)
                    except OSError:
                        pass
            except (ssl.SSLError, OSError):
                pass

    def __exit__(self, *exc: Any) -> None:
        self._stop.set()
        self._sock.close()
        self._t.join(timeout=3)


@pytest.mark.parametrize("version,label", [
    (ssl.TLSVersion.TLSv1, "TLSv1.0"),
    (ssl.TLSVersion.TLSv1_1, "TLSv1.1"),
])
def test_legacy_tls_version_is_detected(version, label):
    """Regression: under OpenSSL 3 the TLS 1.0 and 1.1 probes failed on the client side with
    "[SSL] internal error" before sending a ClientHello, because Python's default cipher string
    carries @SECLEVEL=2 and no cipher or signature is allowed for those versions above level 0.
    Every legacy-protocol endpoint was reported as not offering TLS 1.0/1.1. On the public dataset
    the reference (openssl s_client -tls1 / -tls1_1) found 59 such endpoints; Morrow found none.
    """
    with _Server(version, "ALL:@SECLEVEL=0") as server:
        got = scanner._probe_tls_versions("127.0.0.1", server.port)
    assert got["tls_support_map"][label] is True, got["tls_probe_errors"]
    assert label in got["tls_supported_versions"]


def test_tls12_server_with_only_rsa_key_exchange_is_detected():
    """Regression: the TLS 1.2 probe used Python's default ciphers, which exclude static-RSA key
    exchange, so a TLS 1.2 server offering only AES*-GCM-SHA* with RSA key transport (public
    example: static-rsa.badssl.com) was reported as not speaking TLS 1.2 at all."""
    with _Server(ssl.TLSVersion.TLSv1_2, "AES256-GCM-SHA384:AES128-GCM-SHA256") as server:
        got = scanner._probe_tls_versions("127.0.0.1", server.port)
    assert got["tls_support_map"]["TLSv1.2"] is True, got["tls_probe_errors"]


def test_modern_server_is_still_reported_without_legacy_versions():
    """The fix must not invent legacy support: a TLS 1.2/1.3 server refuses 1.0 and 1.1."""
    with _Server(ssl.TLSVersion.TLSv1_2, "ECDHE+AESGCM") as server:
        got = scanner._probe_tls_versions("127.0.0.1", server.port)
    assert got["tls_support_map"]["TLSv1.2"] is True
    assert got["tls_support_map"]["TLSv1.0"] is False
    assert got["tls_support_map"]["TLSv1.1"] is False



def test_certificate_is_read_from_a_static_rsa_only_server():
    """Regression: the primary handshake uses ssl.create_default_context(), which has no static-RSA
    key exchange. Against static-rsa.badssl.com it failed with a handshake_failure alert and the
    scan came back tls_error with no certificate, so the endpoint was "unknown" instead of
    "RSA 2048, quantum-vulnerable"."""
    with _Server(ssl.TLSVersion.TLSv1_2, "AES256-GCM-SHA384") as server:
        facts = scanner.scan_host("127.0.0.1", server.port)
    assert facts["scan_status"] == "ok", (facts["scan_status"], facts.get("error"))
    assert (facts["key_type"], facts["key_bits"]) == ("RSA", 2048)
    assert facts["unverified_fallback"] is True
    assert facts["primary_handshake_error"]
    assert facts["classical_crypto_dependency"] is True


# ── Hybrid key exchange: a server that prefers a share it already has ────────────────────────────

def _client_hello_key_share_groups(data: bytes) -> list:
    """(group, share length) pairs in the key_share extension of a raw ClientHello record."""
    body = data[9:]
    pos = 2 + 32
    pos += 1 + body[pos]                                            # session id
    pos += 2 + int.from_bytes(body[pos:pos + 2], "big")             # cipher suites
    pos += 1 + body[pos]                                            # compression
    end = pos + 2 + int.from_bytes(body[pos:pos + 2], "big")
    pos += 2
    while pos + 4 <= end:
        etype = int.from_bytes(body[pos:pos + 2], "big")
        elen = int.from_bytes(body[pos + 2:pos + 4], "big")
        ext = body[pos + 4:pos + 4 + elen]
        pos += 4 + elen
        if etype == 0x0033:
            groups, p = [], 2
            while p + 4 <= len(ext):
                g = int.from_bytes(ext[p:p + 2], "big")
                n = int.from_bytes(ext[p + 2:p + 4], "big")
                groups.append((g, n))
                p += 4 + n
            return groups
    return []


class _ShareTakingServer:
    """Replays what the missed public servers do: pick the most preferred group the client sent a
    key share for, and never send a HelloRetryRequest. Supported: X25519MLKEM768, then X25519."""

    def __init__(self) -> None:
        self.port = 0
        self.seen: list = []
        self._stop = threading.Event()

    @staticmethod
    def _server_hello(session_id: bytes, group: int, share_len: int) -> bytes:
        def u16(v: int) -> bytes:
            return v.to_bytes(2, "big")
        share = b"\x00" * share_len
        exts = u16(0x002B) + u16(2) + u16(0x0304)
        exts += u16(0x0033) + u16(4 + share_len) + u16(group) + u16(share_len) + share
        body = (u16(0x0303) + os.urandom(32) + bytes([len(session_id)]) + session_id
                + u16(0x1301) + b"\x00" + u16(len(exts)) + exts)
        hs = b"\x02" + len(body).to_bytes(3, "big") + body
        return b"\x16\x03\x03" + u16(len(hs)) + hs

    def __enter__(self) -> "_ShareTakingServer":
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(4)
        self._sock.settimeout(0.5)
        self.port = self._sock.getsockname()[1]

        def serve() -> None:
            while not self._stop.is_set():
                try:
                    raw, _ = self._sock.accept()
                except (socket.timeout, OSError):
                    continue
                try:
                    raw.settimeout(3)
                    data = b""
                    while len(data) < 5 or len(data) < 5 + int.from_bytes(data[3:5], "big"):
                        chunk = raw.recv(65536)
                        if not chunk:
                            break
                        data += chunk
                    shares = _client_hello_key_share_groups(data)
                    self.seen.append(shares)
                    offered = {g for g, _ in shares}
                    sid_off = 5 + 4 + 2 + 32
                    sid = data[sid_off + 1:sid_off + 1 + data[sid_off]]
                    group, n = (0x11EC, 1120) if 0x11EC in offered else (0x001D, 32)
                    raw.sendall(self._server_hello(sid, group, n))
                except OSError:
                    pass
                finally:
                    raw.close()

        self._t = threading.Thread(target=serve, daemon=True)
        self._t.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self._stop.set()
        self._sock.close()
        self._t.join(timeout=3)


def test_hybrid_server_that_prefers_an_existing_share_is_seen_as_hybrid():
    """Regression: the probe sent only an X25519 key share. A server supporting X25519MLKEM768
    that takes an offered share rather than asking for another (no HelloRetryRequest) answered
    X25519, and Morrow reported classical key exchange. 137 of 299 hybrid-capable public endpoints
    were missed that way (pypi.org, www.apple.com, www.mozilla.org, www.nytimes.com, ...)."""
    with _ShareTakingServer() as server:
        got = scanner._probe_key_exchange_group("127.0.0.1", server.port)
    assert got["key_exchange_observed"] is True, got["key_exchange_unobservable_reason"]
    assert got["key_exchange"] == "X25519MLKEM768"
    assert got["key_exchange_family"] == "pq_hybrid"
    assert got["key_exchange_hello_retry"] is False
    # The ClientHello is browser-shaped: a 1216-byte hybrid share first, then X25519.
    assert server.seen[0] == [(0x11EC, 1216), (0x001D, 32)]


def test_mlkem_encapsulation_key_is_well_formed():
    """A server runs the FIPS 203 modulus check on the key; every coefficient must be below q."""
    ek = scanner._mlkem768_encapsulation_key()
    assert len(ek) == 1184
    packed = ek[:1152]
    for i in range(0, len(packed), 3):
        b0, b1, b2 = packed[i], packed[i + 1], packed[i + 2]
        assert (b0 | ((b1 & 0x0F) << 8)) < 3329
        assert ((b1 >> 4) | (b2 << 4)) < 3329


# ── Harvest-now-decrypt-later verdict ──────────────────────────────────────────────────────────

def _readiness(**facts):
    import policy
    base = {"host": "example.test", "tls_supported_versions": ["TLSv1.2", "TLSv1.3"],
            "key_type": "EC", "key_detail": "secp256r1", "subject": "CN=example.test",
            "scan_status": "ok"}
    base.update(facts)
    return policy.derive_quantum_readiness(base, [])


def test_hybrid_key_exchange_is_not_reported_as_harvest_now_decrypt_later_exposed():
    """Regression: the HNDL verdict looked only at the certificate key and TLS version, never at
    the key exchange, so endpoints negotiating X25519MLKEM768 (Google, Cloudflare, Meta, AWS...)
    were reported HNDL "critical"/"high": 310 of 386 public endpoints wrong, precision 20%."""
    pq = _readiness(key_exchange_observed=True, key_exchange_family="pq_hybrid", key_exchange="X25519MLKEM768")
    assert pq["harvest_now_decrypt_later_risk"] == "low"
    # The certificate is still classical: impersonation risk is unchanged.
    assert pq["classical_crypto_dependency"] is True


def test_classical_or_unobserved_key_exchange_keeps_hndl_exposed():
    assert _readiness(key_exchange_observed=True, key_exchange_family="classical")["harvest_now_decrypt_later_risk"] == "high"
    # A group that was not observed is not evidence of protection.
    assert _readiness(key_exchange_observed=False, key_exchange_family="pq_hybrid")["harvest_now_decrypt_later_risk"] == "high"
    assert _readiness(tls_supported_versions=["TLSv1.2"], key_exchange_observed=True,
                      key_exchange_family="classical")["harvest_now_decrypt_later_risk"] == "critical"
