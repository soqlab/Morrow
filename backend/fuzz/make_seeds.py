"""Regenerate the seed corpus under backend/fuzz/corpus/ (run from backend/).

    python -m fuzz.make_seeds            # synthetic seeds and fixtures
    python -m fuzz.make_seeds --capture  # also capture real first flights from a local OpenSSL

Seeds are spec-shaped messages (built here), the IKE datagrams strongSwan 6.1.0 sent
(tests/fixtures/ike), the log lines of test_passive_discovery.py and certificates generated with
cryptography. --capture records what this machine's OpenSSL server sends back to the scanner's
real ClientHello, for each key-exchange group it supports. Regression inputs live in
corpus/<target>/regressions/ and are never rewritten here.
"""

from __future__ import annotations

import datetime
import json
import pathlib
import socket
import ssl
import struct
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parent
CORPUS = ROOT / "corpus"
BACKEND = ROOT.parent


def _write(target: str, name: str, data: bytes) -> None:
    folder = CORPUS / target
    folder.mkdir(parents=True, exist_ok=True)
    (folder / name).write_bytes(data)


def _u16(v: int) -> bytes:
    return struct.pack(">H", v)


def _record(rtype: int, payload: bytes) -> bytes:
    return bytes([rtype, 3, 3]) + _u16(len(payload)) + payload


def _hs(mtype: int, body: bytes) -> bytes:
    return bytes([mtype]) + len(body).to_bytes(3, "big") + body


def _server_hello(random: bytes, exts: bytes, sid: bytes = b"\x11" * 32, suite: int = 0x1301) -> bytes:
    body = _u16(0x0303) + random + bytes([len(sid)]) + sid + _u16(suite) + b"\x00"
    if exts is not None:
        body += _u16(len(exts)) + exts
    return body


def tls_seeds() -> None:
    import scanner

    rnd = bytes(range(32))
    ks = _u16(0x0033) + _u16(36) + _u16(0x001D) + _u16(32) + b"\x42" * 32
    sv = _u16(0x002B) + _u16(2) + _u16(0x0304)
    sh13 = _server_hello(rnd, sv + ks)
    hrr = _server_hello(scanner._HRR_RANDOM, sv + _u16(0x0033) + _u16(2) + _u16(0x11EC))
    sh12 = _server_hello(rnd, _u16(0xFF01) + _u16(1) + b"\x00", sid=b"", suite=0xC02F)
    sh12_noext = _server_hello(rnd, None, sid=b"", suite=0x002F)
    cert = _hs(11, (303).to_bytes(3, "big") + (300).to_bytes(3, "big") + b"\x30" * 300)
    ske = _hs(12, b"\x03" + _u16(0x0017) + bytes([65]) + b"\x04" * 65 + _u16(0x0401) + _u16(16) + b"\x99" * 16)
    shd = _hs(14, b"")
    for name, body in (("sh13-x25519", sh13), ("hrr-x25519mlkem768", hrr), ("sh12", sh12),
                       ("sh12-noext", sh12_noext)):
        _write("tls_server_hello", f"{name}.bin", body)
    _write("tls_flight", "tls13-x25519.bin", _record(22, _hs(2, sh13)) + _record(20, b"\x01"))
    _write("tls_flight", "hrr-x25519mlkem768.bin", _record(22, _hs(2, hrr)))
    flight12 = _hs(2, sh12) + cert + ske + shd
    _write("tls_flight", "tls12-secp256r1.bin", _record(22, flight12))
    _write("tls_flight", "tls12-split-records.bin",
           b"".join(_record(22, flight12[i:i + 50]) for i in range(0, len(flight12), 50)))
    _write("tls_flight", "tls12-static-rsa.bin", _record(22, _hs(2, sh12_noext) + cert + shd))
    _write("tls_flight", "alert-handshake-failure.bin", _record(21, b"\x02\x28"))


def capture_tls() -> None:
    """Real first flights: this machine's OpenSSL answering scanner._build_client_hello."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    import scanner

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fuzz.example")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(7).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=2))
            .sign(key, hashes.SHA256()))
    tmp = pathlib.Path(tempfile.mkdtemp())
    (tmp / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                  serialization.NoEncryption()))
    cases = [("X25519MLKEM768", ssl.TLSVersion.TLSv1_3), ("X25519", ssl.TLSVersion.TLSv1_3),
             ("secp384r1", ssl.TLSVersion.TLSv1_3), ("secp521r1", ssl.TLSVersion.TLSv1_2)]
    for group, version in cases:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ctx.maximum_version = version
        try:
            ctx.set_ecdh_curve(group)
        except (ValueError, ssl.SSLError):
            print(f"skip {group}: not supported by this OpenSSL")
            continue
        ctx.load_cert_chain(tmp / "c.pem", tmp / "k.pem")
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        def serve() -> None:
            conn, _ = srv.accept()
            try:
                with ctx.wrap_socket(conn, server_side=True):
                    pass
            except (ssl.SSLError, OSError):
                pass

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        with socket.create_connection(("127.0.0.1", port), timeout=3) as c:
            c.sendall(scanner._build_client_hello("fuzz.example"))
            data, end = b"", time.monotonic() + 1.5
            c.settimeout(0.3)
            while time.monotonic() < end and len(data) < 65536:
                try:
                    chunk = c.recv(16384)
                except socket.timeout:
                    continue
                if not chunk:
                    break
                data += chunk
        srv.close()
        t.join(timeout=2)
        _write("tls_flight", f"openssl-{group.lower()}-{version.name.lower()}.bin", data)
        print(f"captured {group}: {len(data)} bytes")


def x509_seeds() -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    keys = [("rsa2048", rsa.generate_private_key(65537, 2048), hashes.SHA256()),
            ("p384", ec.generate_private_key(ec.SECP384R1()), hashes.SHA384()),
            ("ed25519", ed25519.Ed25519PrivateKey.generate(), None)]
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa

        keys.append(("mldsa65", mldsa.MLDSA65PrivateKey.generate(), None))
    except (ImportError, AttributeError):
        pass
    for label, key, digest in keys:
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{label}.fuzz.example"),
                          x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Fuzz")])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(1000).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=90))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(f"{label}.fuzz.example")]), False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
                .add_extension(x509.AuthorityInformationAccess([x509.AccessDescription(
                    x509.oid.AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier("http://ocsp.fuzz.example"))]), False)
                .add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
                    [x509.UniformResourceIdentifier("http://crl.fuzz.example/c.crl")], None, None, None)]), False)
                .sign(key, digest))
        _write("x509", f"{label}.der", cert.public_bytes(serialization.Encoding.DER))


def ike_seeds() -> None:
    import ike_scanner as ike

    for path in sorted((BACKEND / "tests" / "fixtures" / "ike").glob("*.json")):
        responses = json.loads(path.read_text(encoding="utf-8"))["responses"]
        unique = []
        for resp in responses:
            if resp and resp[32:] not in [u[32:] for u in unique]:
                unique.append(resp)
        for i, resp in enumerate(unique[:6]):
            _write("ike", f"{path.stem}-{i}.bin", bytes.fromhex(resp))
    icookie = b"\x07" * 8
    req = ike.build_ikev1_main_mode(icookie)
    _write("ikev1", "main-mode-offer.bin", req)
    v2_notify = icookie + b"\x00" * 8 + struct.pack(">BBBBII", 41, 0x20, 2, 0, 0, 36) + \
        struct.pack(">BBHBBH", 0, 0, 8, 0, 0, 5)
    _write("ikev1", "ikev2-invalid-major-version.bin", v2_notify)


def ssh_seeds() -> None:
    sys.path.insert(0, str(BACKEND))
    from test_ssh_scanner_accuracy import _kexinit_packet

    pkt = _kexinit_packet(["mlkem768x25519-sha256", "curve25519-sha256"], ["ssh-ed25519", "rsa-sha2-512"],
                          ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"],
                          ["hmac-sha2-256-etm@openssh.com"])
    _write("ssh", "openssh-9.6.bin", b"SSH-2.0-OpenSSH_9.6\r\n" + pkt)
    _write("ssh", "empty-lists.bin", b"SSH-2.0-Minimal\r\n" + _kexinit_packet([], [], [], []))
    _write("ssh_kexinit", "kexinit.bin", pkt[5:-8])


def passive_seeds() -> None:
    sys.path.insert(0, str(BACKEND))
    import test_passive_discovery as T

    lines = {k: v for k, v in vars(T).items() if k.isupper() and isinstance(v, (str, list)) and k not in ("ORG_A", "ORG_B")}
    for name, value in lines.items():
        text = "\n".join(value) if isinstance(value, list) else value
        _write("passive", f"{name.lower()}.txt", b"\x03" + text.encode())
        if text.startswith("{"):
            _write("passive", f"{name.lower()}-json-array.txt", b"\x01" + ("[" + text + "]").encode())


def bom_seeds() -> None:
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
        {"type": "library", "name": "openssl", "version": "3.0.13",
         "components": [{"type": "cryptographic-asset", "name": "RSA-2048",
                         "cryptoProperties": {"algorithmProperties": {"primitive": "pke",
                                                                      "parameterSetIdentifier": "2048"}}}]},
        {"type": "library", "name": "bouncycastle", "properties": [{"name": "algorithm", "value": "ML-KEM-768"},
                                                                    {"name": "keyLength", "value": "768"}]}]}
    _write("sbom", "synthetic-sbom-1.5.json", json.dumps(sbom).encode())
    cbom_dir = BACKEND / "tests" / "fixtures" / "cbomkit"
    for path in sorted(cbom_dir.glob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        doc["components"] = doc.get("components", [])[:12]        # small seeds fuzz faster
        _write("cbom", f"{path.stem}-small.json", json.dumps(doc).encode())
    _write("cbom_ingest", "ci-cbom.json", json.dumps({"bomFormat": "CycloneDX", "metadata": {"component": {"name": "repo"}},
                                                     "components": [{"name": "RSA", "cryptoProperties": {
                                                         "algorithmProperties": {"primitive": "pke"}}}]}).encode())


def cert_inventory_seeds() -> None:
    values = {"iso": "2027-03-01T12:00:00.1234567Z", "dotnet": "/Date(1798761600000)/", "epoch": 1798761600,
              "rsa": "RSA", "ec": "EC_secp384r1", "mldsa": "ML-DSA-65", "size": "4096",
              "thumbprint": "AB:CD:" * 9 + "AB:CD", "jwk_n": "u1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gunVTLw"}
    for name, value in values.items():
        _write("cert_inventory", f"{name}.json", json.dumps(value).encode())


def main(argv: list) -> None:
    sys.path.insert(0, str(BACKEND))
    cert_inventory_seeds()
    tls_seeds()
    x509_seeds()
    ike_seeds()
    ssh_seeds()
    passive_seeds()
    bom_seeds()
    if "--capture" in argv:
        capture_tls()


if __name__ == "__main__":
    main(sys.argv[1:])
