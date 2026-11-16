"""Paste anything (services/paste_anything.py, services/pcap_tls.py, routers/paste.py).

Detection for every kind, ambiguous and malicious input, the private-key refusal, the per-type
limits, the anonymous rate limits, and the promise that nothing pasted is stored, logged or echoed.
No network: nothing here connects anywhere, and the tests check that a paste never tries to.
"""

import base64
import json
import os
import socket
import struct
import time
from datetime import datetime, timedelta, timezone

os.environ.setdefault("MORROW_AUTH_JWT_SECRET", "test-secret-for-unit-tests-only-x9z7q8r1m2n3")
os.environ.setdefault("MORROW_LLM_DISABLED", "1")

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from services import org_rate_limits as _limits
from services import paste_anything as pa
from services import pcap_tls


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("MORROW_SCANNER_DB", str(tmp_path / "paste.db"))
    monkeypatch.setenv("MORROW_FEATURE_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("MORROW_PUBLIC_CHECK_IP_SALT", "test-salt")
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.delenv("CELERY_BROKER_URL", raising=False)
    _limits.reset()

    def no_network(*a, **k):
        raise AssertionError("a paste tried to open a connection")

    monkeypatch.setattr(socket, "create_connection", no_network)
    monkeypatch.setattr(socket, "getaddrinfo", no_network)
    yield
    _limits.reset()


def run(text, name="", forced=""):
    data = text if isinstance(text, bytes) else text.encode("utf-8")
    return pa.analyze(data, name, forced)


def refused(text, name="", forced=""):
    with pytest.raises(pa.PasteError) as info:
        run(text, name, forced)
    return info.value


# ── certificates ─────────────────────────────────────────────────────────────

def _cert(key, subject, issuer_name=None, issuer_key=None, days=90, sans=("example.com",), ca=False):
    now = datetime.now(timezone.utc)
    builder = (x509.CertificateBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
               .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name or subject)]))
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=days))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
    return builder.sign(issuer_key or key, hashes.SHA256())


@pytest.fixture(scope="module")
def keys():
    return {"rsa": rsa.generate_private_key(public_exponent=65537, key_size=2048),
            "ec": ec.generate_private_key(ec.SECP256R1())}


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def test_a_pem_certificate_is_read_with_key_signature_expiry_and_verdict(keys):
    r = run(pem(_cert(keys["rsa"], "example.com")))
    assert r["kind"] == "certificate"
    item = r["details"]["items"][0]
    assert item["key"] == "RSA 2048-bit" and item["signature_algorithm"] == "RSA with SHA-256"
    assert item["quantum_vulnerable"] is True and item["tone"] == "bad"
    assert 85 <= item["days_left"] <= 90 and not item["expired"]
    assert "for example.com" in r["what"]
    # Harvest-clock relevance: the certificate does not decide recorded-traffic exposure.
    assert "key exchange does" in r["harvest"][0]
    assert any("before 2035" in h for h in r["harvest"])
    assert any("RSA key transport" in h for h in r["harvest"])
    assert r["next"][0]["href"] == "/r/example.com"
    assert r["stored"] is False and "discarded" in r["privacy"]


def test_a_chain_der_and_one_line_base64_are_read(keys):
    root = _cert(keys["ec"], "Root CA", ca=True, sans=(), days=3650)
    leaf = _cert(keys["rsa"], "www.example.org", issuer_name="Root CA", issuer_key=keys["ec"],
                 sans=("*.example.org", "www.example.org"), days=4000)
    r = run(pem(leaf) + "\n" + pem(root))
    assert r["kind"] == "certificate" and len(r["details"]["items"]) == 2
    assert r["details"]["chain_in_order"] is True
    assert r["details"]["items"][1]["key"] == "EC P-256"
    assert any("could forge it while it is still trusted" in h for h in r["harvest"])
    assert r["next"][0]["href"] == "/r/www.example.org"          # wildcard skipped
    der = leaf.public_bytes(serialization.Encoding.DER)
    assert run(der, "server.der")["kind"] == "certificate"
    assert run(base64.b64encode(der).decode())["kind"] == "certificate"
    reversed_chain = run(pem(root) + pem(leaf))
    assert reversed_chain["details"]["chain_in_order"] is False


def test_a_csr_and_a_public_key_are_read(keys):
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")]))
           .sign(keys["ec"], hashes.SHA256()))
    r = run(csr.public_bytes(serialization.Encoding.PEM).decode())
    assert r["kind"] == "certificate" and r["details"]["items"][0]["role"] == "request"
    pub = keys["rsa"].public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    r = run(pub)
    assert r["details"]["items"][0]["role"] == "public_key" and r["what"] == "A public key."


def test_a_broken_certificate_block_is_a_plain_400():
    err = refused("-----BEGIN CERTIFICATE-----\nMIIBAAAA\n-----END CERTIFICATE-----")
    assert err.status_code == 400 and err.error == "unreadable"


# ── private keys: refused, discarded, warned ─────────────────────────────────

@pytest.mark.parametrize("fmt", ["traditional", "pkcs8", "openssh"])
def test_a_pasted_private_key_is_refused_with_a_plain_warning(keys, fmt, caplog):
    form = {"traditional": serialization.PrivateFormat.TraditionalOpenSSL, "pkcs8": serialization.PrivateFormat.PKCS8,
            "openssh": serialization.PrivateFormat.OpenSSH}[fmt]
    key = keys["ec"].private_bytes(serialization.Encoding.PEM, form, serialization.NoEncryption()).decode()
    err = refused(key)
    assert err.status_code == 422 and err.error == "private_key"
    body = err.as_dict()
    assert body["refused"] is True and "Treat the key as exposed" in body["detail"]
    assert key.splitlines()[1] not in json.dumps(body)
    assert key.splitlines()[1] not in caplog.text


def test_a_private_key_hidden_in_a_config_or_next_to_a_certificate_is_refused(keys):
    key = keys["rsa"].private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.BestAvailableEncryption(b"pw")).decode()
    assert refused("server {\n ssl_protocols TLSv1.3;\n}\n" + key).error == "private_key"
    assert refused(pem(_cert(keys["rsa"], "a.example")) + key).error == "private_key"


def test_der_pkcs8_pkcs12_keystores_putty_and_jwk_private_keys_are_refused(keys):
    from cryptography.hazmat.primitives.serialization import pkcs12

    der = keys["ec"].private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    assert refused(der).error == "private_key"
    p12 = pkcs12.serialize_key_and_certificates(b"x", keys["ec"], None, None, serialization.BestAvailableEncryption(b"pw"))
    assert refused(p12).error == "private_key"
    assert refused(b"anything", "keystore.jks").error == "private_key"
    assert refused("PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n").error == "private_key"
    assert refused(json.dumps({"keys": [{"kty": "EC", "crv": "P-256", "x": "a", "y": "b", "d": "secret"}]})).error == "private_key"


# ── configuration files ──────────────────────────────────────────────────────

NGINX_OFF = """
http {
  server {
    listen 443 ssl;
    server_name example.com;
    ssl_certificate /etc/ssl/example.pem;
    ssl_protocols TLSv1 TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:AES128-SHA:!aNULL;
    ssl_ecdh_curve X25519:prime256v1;
  }
}
"""


def test_nginx_with_a_classical_curve_list_is_off_with_the_recipe():
    r = run(NGINX_OFF)
    assert r["kind"] == "config" and r["stack"] == "nginx" and r["hybrid_pq"] == "off"
    assert r["details"]["protocols"] == ["TLSv1.0", "TLSv1.2", "TLSv1.3"]
    assert r["details"]["groups"] == ["X25519", "prime256v1"]
    assert any("Old protocol versions" in f for f in r["findings"])
    assert any("RSA key transport" in f and "AES128-SHA" in f for f in r["findings"])
    assert r["recipe"]["id"] == "nginx" and "ssl_ecdh_curve X25519MLKEM768" in r["recipe"]["snippet"]
    assert any("2035" in h for h in r["harvest"])
    # Only the TLS settings are quoted back, never the other lines (paths, names).
    assert "/etc/ssl/example.pem" not in json.dumps(r)


def test_nginx_on_and_nginx_default():
    on = run(NGINX_OFF.replace("X25519:prime256v1", "X25519MLKEM768:X25519").replace("TLSv1 ", ""))
    assert on["hybrid_pq"] == "on" and on["tone"] == "ok"
    default = run("server {\n listen 443 ssl;\n ssl_protocols TLSv1.2 TLSv1.3;\n server_name a.example;\n}\n")
    assert default["hybrid_pq"] == "default" and "OpenSSL 3.5" in default["findings"][0]
    auto = run("server {\n listen 443 ssl;\n ssl_ecdh_curve auto;\n ssl_protocols TLSv1.3;\n}\n")
    assert auto["hybrid_pq"] == "default"


def test_tls13_switched_off_means_hybrid_is_off_even_with_the_group():
    r = run("server {\n listen 443 ssl;\n ssl_protocols TLSv1.2;\n ssl_ecdh_curve X25519MLKEM768:X25519;\n}\n")
    assert r["hybrid_pq"] == "off" and any("TLS 1.3 is not enabled" in f for f in r["findings"])


def test_apache_haproxy_caddy_traefik():
    apache = run("<VirtualHost *:443>\n  ServerName example.com\n  SSLEngine on\n  SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1\n"
                 "  SSLOpenSSLConfCmd Groups X25519MLKEM768:X25519\n  SSLCipherSuite HIGH:!aNULL\n</VirtualHost>\n")
    assert apache["stack"] == "apache" and apache["hybrid_pq"] == "on"
    assert apache["details"]["protocols"] == ["TLSv1.2", "TLSv1.3"] and apache["recipe"]["id"] == "apache"

    haproxy = run("global\n    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tlsv13\n    ssl-default-bind-curves X25519:P-256\n"
                  "defaults\n    mode http\nfrontend web\n    bind :443 ssl crt /etc/haproxy/site.pem\n    default_backend app\n")
    assert haproxy["stack"] == "haproxy" and haproxy["hybrid_pq"] == "off"
    assert haproxy["details"]["protocols"] == ["TLSv1.2"]
    assert "ssl-default-bind-curves X25519MLKEM768" in haproxy["recipe"]["snippet"]

    caddy = run("example.com {\n\treverse_proxy localhost:8080\n\ttls {\n\t\tprotocols tls1.2 tls1.3\n\t\tcurves x25519 secp256r1\n\t}\n}\n")
    assert caddy["stack"] == "caddy" and caddy["hybrid_pq"] == "off" and caddy["recipe"]["id"] == "caddy"

    traefik = run("tls:\n  options:\n    default:\n      minVersion: VersionTLS12\n      curvePreferences:\n"
                  "        - X25519MLKEM768\n        - CurveP256\n")
    assert traefik["stack"] == "traefik" and traefik["hybrid_pq"] == "on"
    assert traefik["details"]["groups"] == ["X25519MLKEM768", "CurveP256"]


def test_openssl_cnf_sshd_java_and_schannel_use_their_own_recipes():
    cnf = run("openssl_conf = openssl_init\n[openssl_init]\nssl_conf = ssl_sect\n[ssl_sect]\nsystem_default = system_default_sect\n"
              "[system_default_sect]\nMinProtocol = TLSv1.2\nGroups = X25519:P-256\nCipherString = DEFAULT@SECLEVEL=2\n")
    assert cnf["stack"] == "openssl_cnf" and cnf["hybrid_pq"] == "off" and cnf["recipe"]["id"] == "openssl_cnf"
    assert cnf["recipe"]["sources"][0]["url"].startswith("https://docs.openssl.org/")

    ssh_default = run("Port 22\nPermitRootLogin no\nPasswordAuthentication no\nHostKey /etc/ssh/ssh_host_rsa_key\n")
    assert ssh_default["stack"] == "openssh" and ssh_default["hybrid_pq"] == "default"
    ssh_on = run("KexAlgorithms mlkem768x25519-sha256,curve25519-sha256\nPasswordAuthentication no\n")
    assert ssh_on["hybrid_pq"] == "on" and ssh_on["recipe"]["id"] == "openssh"
    ssh_append = run("KexAlgorithms +diffie-hellman-group14-sha1\nPermitRootLogin no\n")
    assert ssh_append["hybrid_pq"] == "default" and any("SHA-1" in f for f in ssh_append["findings"])

    java = run("security.provider.1=SUN\njdk.tls.disabledAlgorithms=SSLv3, TLSv1, TLSv1.1, RC4, \\\n    DES, MD5withRSA\n"
               "jdk.tls.namedGroups=x25519,secp256r1\n")
    assert java["stack"] == "java" and java["hybrid_pq"] == "off" and java["recipe"]["id"] == "java"
    assert java["details"]["protocols"] == ["TLSv1.2", "TLSv1.3"]

    reg = ("Windows Registry Editor Version 5.00\r\n\r\n"
           "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server]\r\n"
           "\"Enabled\"=dword:00000000\r\n\"DisabledByDefault\"=dword:00000001\r\n")
    iis = run(reg.encode("utf-16"))
    assert iis["stack"] == "iis" and "TLSv1.0" not in iis["details"]["protocols"]
    assert iis["hybrid_pq"] == "default" and iis["recipe"]["id"] == "iis"
    ps = run('Enable-TlsEccCurve -Name "X25519_MLKEM768" -Position 0\nDisable-TlsCipherSuite -Name "TLS_RSA_WITH_3DES_EDE_CBC_SHA"\n')
    assert ps["stack"] == "iis" and ps["hybrid_pq"] == "on"


def test_an_ambiguous_config_asks_and_the_answer_is_honoured():
    mixed = ("server {\n  listen 443 ssl;\n  ssl_protocols TLSv1.3;\n  ssl_ciphers HIGH;\n}\n"
             "<VirtualHost *:443>\n  SSLProtocol -all +TLSv1.3\n</VirtualHost>\n")
    r = run(mixed)
    assert r["kind"] == "ambiguous"
    assert {c["as"] for c in r["choices"]} >= {"config:nginx", "config:apache"}
    assert run(mixed, forced="config:apache")["stack"] == "apache"
    assert run(mixed, forced="config:nginx")["stack"] == "nginx"


# ── domains, lists, repositories, unknowns ───────────────────────────────────

@pytest.mark.parametrize("text,host", [("example.com", "example.com"), ("https://WWW.Example.com/a?b", "www.example.com"),
                                       ("user@mail.example.net:8443", "mail.example.net")])
def test_a_domain_or_url_goes_to_its_record(text, host):
    r = run(text)
    assert r["kind"] == "domain" and r["redirect"] == f"/r/{host}"


def test_a_list_of_domains_goes_to_the_vendor_check():
    r = run("example.com\nexample.org\nhttps://example.net/\n")
    assert r["kind"] == "domain_list" and r["details"]["count"] == 3 and r["next"][0]["href"] == "/vendors"


@pytest.mark.parametrize("link", ["https://github.com/openssl/openssl", "github.com/a/b.git", "git@github.com:a/b.git",
                                  "https://gitlab.com/group/project/-/tree/main"])
def test_a_repository_link_says_honestly_that_scanning_needs_an_account(link):
    r = run(link)
    assert r["kind"] == "repository"
    assert "nothing was read" in r["headline"]
    assert r["next"][0]["href"] == "/ui/code-hosts.html"


@pytest.mark.parametrize("text", ["not a domain", "hello world\nthis is prose", "wp-login.php", "{\"a\": 1}",
                                  "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><x>&e;</x>",
                                  "<bom xmlns=\"http://cyclonedx.org/schema/bom/1.6\"></bom>"])
def test_text_morrow_does_not_read_is_answered_as_unknown(text):
    r = run(text)
    assert r["kind"] == "unknown"
    assert "/etc/passwd" not in r["headline"] and "root:" not in json.dumps(r)


def test_compressed_files_are_never_opened():
    import gzip
    import io
    import zipfile

    bomb = gzip.compress(b"\0" * 5_000_000)
    assert refused(bomb).status_code == 415
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("a.conf", "x" * 1_000_000)
    assert refused(buf.getvalue()).status_code == 415
    assert refused(b"plain", "x.tar.gz").status_code == 415


# ── CBOM ─────────────────────────────────────────────────────────────────────

def _cbom(*algs):
    comps = [{"type": "cryptographic-asset", "bom-ref": f"a{i}", "name": name,
              "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": prim, "parameterSetIdentifier": p}}}
             for i, (name, prim, p) in enumerate(algs)]
    comps.append({"type": "library", "name": "openssl", "version": "3.5.0"})
    return json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                       "metadata": {"component": {"type": "application", "name": "shop"}}, "components": comps})


def test_a_cbom_is_summarised_by_quantum_risk_and_nothing_is_imported():
    r = run(_cbom(("RSA", "pke", "2048"), ("ECDH", "key-agree", "256"), ("ML-KEM", "kem", "768"), ("AES", "ae", "256")))
    assert r["kind"] == "cbom" and "for shop" in r["what"]
    d = r["details"]
    assert d["assets"] == 4 and d["components"] == 5
    assert len(d["quantum_vulnerable"]) == 2 and d["post_quantum"]
    assert sum(d["by_risk"].values()) == 4
    assert r["headline"].startswith("2 of 4")
    assert r["next"][0]["href"] == "/ui/#cbom"


def test_json_bombs_are_refused_without_a_crash():
    deep = "[" * 5000 + "]" * 5000
    assert run(deep)["kind"] == "unknown"
    with pytest.raises(pa.PasteError):
        run(deep, forced="cbom")
    big = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [], "pad": "x" * (6 * 1024 * 1024)})
    assert refused(big).status_code == 413


# ── captures ─────────────────────────────────────────────────────────────────

def _client_hello(groups, shares, sni="shop.example.com"):
    def ext(t, body):
        return struct.pack("!HH", t, len(body)) + body
    name = sni.encode()
    sni_ext = ext(0, struct.pack("!HBH", len(name) + 3, 0, len(name)) + name)
    sg = b"".join(struct.pack("!H", g) for g in groups)
    ks = b"".join(struct.pack("!HH", g, 32) + b"\x11" * 32 for g in shares)
    exts = (sni_ext + ext(0x000A, struct.pack("!H", len(sg)) + sg) + ext(0x0033, struct.pack("!H", len(ks)) + ks)
            + ext(0x002B, b"\x04\x03\x04\x03\x03"))
    body = b"\x03\x03" + b"\x22" * 32 + b"\x00" + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00" + struct.pack("!H", len(exts)) + exts
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def _server_hello(group):
    key = b"\x22" * (1120 if group == 0x11EC else 32)
    exts = struct.pack("!HHH", 0x002B, 2, 0x0304) + struct.pack("!HHHH", 0x0033, 4 + len(key), group, len(key)) + key
    body = b"\x03\x03" + b"\x33" * 32 + b"\x00" + b"\x13\x01" + b"\x00" + struct.pack("!H", len(exts)) + exts
    hs = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs


def _frame(src, dst, sport, dport, seq, payload, flags=0x18):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 5 << 4, flags, 65535, 0, 0)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp) + len(payload), 0, 0, 64, 6, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    return b"\x00" * 12 + b"\x08\x00" + ip + tcp + payload


def _pcap(frames, ng=False):
    if ng:
        def block(t, body):
            body += b"\x00" * (-len(body) % 4)
            return struct.pack("<II", t, len(body) + 12) + body + struct.pack("<I", len(body) + 12)
        out = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)) + block(1, struct.pack("<HHI", 1, 0, 65535))
        for f in frames:
            out += block(6, struct.pack("<IIIII", 0, 0, 0, len(f), len(f)) + f)
        return out
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for f in frames:
        out += struct.pack("<IIII", 0, 0, len(f), len(f)) + f
    return out


def _conversation(cport, group, split_client=False):
    c, s = "10.0.0.2", "93.184.216.34"
    ch = _client_hello([0x11EC, 0x001D, 0x0017], [0x11EC, 0x001D])
    frames = [_frame(c, s, cport, 443, 1000, b"", 0x02), _frame(s, c, 443, cport, 5000, b"", 0x12)]
    if split_client:
        frames += [_frame(c, s, cport, 443, 1001, ch[:60]), _frame(c, s, cport, 443, 1001 + 60, ch[60:])]
    else:
        frames.append(_frame(c, s, cport, 443, 1001, ch))
    sh = _server_hello(group)
    frames += [_frame(s, c, 443, cport, 5001, sh[:700]), _frame(s, c, 443, cport, 5001 + 700, sh[700:])]
    return frames


@pytest.mark.parametrize("ng", [False, True])
def test_a_capture_reports_the_negotiated_group_per_connection(ng):
    frames = _conversation(50000, 0x11EC, split_client=True) + _conversation(50001, 0x001D)
    r = run(_pcap(frames, ng=ng), "trace.pcapng" if ng else "trace.pcap")
    assert r["kind"] == "capture"
    d = r["details"]
    assert d["tls_connections"] == 2 and d["post_quantum"] == 1 and d["classical"] == 1
    groups = {c["negotiated_group"] for c in d["connections"]}
    assert groups == {"X25519MLKEM768", "x25519"}
    assert all(c["sni"] == "shop.example.com" and c["client_offers_pq"] for c in d["connections"])
    assert all(c["version"] == "TLS 1.3" for c in d["connections"])
    assert r["headline"] == "1 of 2 connections used a classical key exchange."
    assert r["next"][0]["href"] == "/r/shop.example.com"


def test_capture_limits_packets_time_and_garbage(monkeypatch):
    frames = _conversation(50000, 0x001D) * 3
    monkeypatch.setattr(pcap_tls, "MAX_PACKETS", 3)
    r = pcap_tls.analyze(_pcap(frames))
    assert "stopped after 3 packets" in r["stopped"]
    monkeypatch.setattr(pcap_tls, "MAX_PACKETS", 200_000)
    ticks = iter(range(0, 10_000, 100))
    r = pcap_tls.analyze(_pcap(frames * 200), clock=lambda: next(ticks))
    assert "seconds" in r["stopped"]
    # Truncated, lying and random captures end the walk instead of raising.
    good = _pcap(frames)
    for bad in (good[:30], good[:24] + struct.pack("<IIII", 0, 0, 0xFFFFFFF0, 0xFFFFFFF0) + b"x" * 64,
                b"\xd4\xc3\xb2\xa1" + os.urandom(4000), pcap_tls.PCAPNG_MAGIC + os.urandom(4000)):
        try:
            out = pcap_tls.analyze(bad)
            assert out["tls_connections"] == 0
        except pcap_tls.CaptureError:
            pass
    with pytest.raises(pa.PasteError) as info:
        run(b"\xd4\xc3\xb2\xa1" + b"\0" * (pcap_tls.MAX_BYTES + 1))
    assert info.value.status_code == 413


def test_garbage_tls_inside_a_capture_is_not_trusted():
    c, s = "10.0.0.2", "10.0.0.3"
    frames = [_frame(c, s, 40000, 443, 1, b"\x16\x03\x01\xff\xff" + os.urandom(300)),
              _frame(s, c, 443, 40000, 1, b"\x16\x03\x03\x00\x05\x02\x00\x00\x01\x00")]
    r = pcap_tls.analyze(_pcap(frames))
    assert r["post_quantum"] == 0


# ── limits, the request, rate limits ─────────────────────────────────────────

def test_size_limits_per_type(keys):
    big_cert = pem(_cert(keys["rsa"], "a.example")) + "#" * (pa.LIMITS["certificate"] + 1)
    assert refused(big_cert, forced="certificate").status_code == 413
    assert refused("ssl_protocols TLSv1.3;\n" * 80_000).status_code == 413
    with pytest.raises(pa.PasteError) as info:
        pa.decode_request({"content": base64.b64encode(b"x" * (pa.MAX_INPUT_BYTES + 1)).decode(), "encoding": "base64"})
    assert info.value.status_code == 413
    for bad in ({}, {"content": ""}, {"content": "x", "encoding": "rot13"}, {"content": "x", "as": "exe"}, []):
        with pytest.raises(pa.PasteError):
            pa.decode_request(bad)


def test_pathological_lines_finish_quickly():
    start = time.monotonic()
    for text in ("tls " + "a " * 4000 + "\n", "a." * 4000 + "\n" + "x\n", "bind " + "a:1" * 3000 + "\n",
                 "\n" * 15000 + "server {", "-----BEGIN CERTIFICATE-----" * 5000, " " * 900_000):
        try:
            run(text)
        except pa.PasteError:
            pass
    assert time.monotonic() - start < 10


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("MORROW_AUTH_MODE", "header")
    import app as application

    application.limiter.enabled = False
    with TestClient(application.app, raise_server_exceptions=False) as test_client:
        yield test_client
    application._requests_by_org.clear()


def test_the_api_answers_json_only_and_never_caches(client, caplog):
    secret_line = "ssl_password_file /etc/keys/very-secret-passphrases;"
    r = client.post("/api/public/paste", json={"content": NGINX_OFF + secret_line})
    assert r.status_code == 200 and r.json()["kind"] == "config"
    assert r.headers["cache-control"] == "no-store"
    assert "very-secret" not in r.text and "very-secret" not in caplog.text
    assert client.post("/api/public/paste", content=b"content=x", headers={"content-type": "application/x-www-form-urlencoded"}).status_code == 415
    assert client.post("/api/public/paste", content=b"{", headers={"content-type": "application/json"}).status_code == 400
    capture = _pcap(_conversation(50000, 0x11EC))
    r = client.post("/api/public/paste", json={"content": base64.b64encode(capture).decode(), "encoding": "base64", "name": "a.pcap"})
    assert r.status_code == 200 and r.json()["details"]["post_quantum"] == 1


def test_a_private_key_through_the_api_is_422_and_not_echoed(client, keys):
    key = keys["ec"].private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()).decode()
    r = client.post("/api/public/paste", json={"content": key})
    assert r.status_code == 422 and r.json()["kind"] == "private_key"
    assert key.splitlines()[1] not in r.text


def test_anonymous_pastes_share_the_public_grade_budget(client, monkeypatch):
    monkeypatch.setenv("MORROW_PUBLIC_GRADE_IP_PER_MINUTE", "3")
    monkeypatch.setenv("MORROW_PUBLIC_GRADE_FRESH_PER_MINUTE", "1")
    codes = [client.post("/api/public/paste", json={"content": "example.com"}).status_code for _ in range(4)]
    assert codes == [200, 200, 200, 429]
    _limits.reset()
    capture = base64.b64encode(_pcap(_conversation(50000, 0x001D))).decode()
    first = client.post("/api/public/paste", json={"content": capture, "encoding": "base64"})
    second = client.post("/api/public/paste", json={"content": capture, "encoding": "base64"})
    assert first.status_code == 200 and second.status_code == 429 and int(second.headers["retry-after"]) >= 1


def test_the_body_cap_is_enforced_before_parsing(client):
    r = client.post("/api/public/paste", content=b"{" + b" " * (pa.MAX_BODY_BYTES + 10) + b"}",
                    headers={"content-type": "application/json"})
    assert r.status_code == 413


def test_nothing_pasted_is_written_to_the_database(client, tmp_path):
    client.post("/api/public/paste", json={"content": NGINX_OFF})
    db = tmp_path / "paste.db"
    if db.exists():
        assert b"ssl_ecdh_curve" not in db.read_bytes()


def test_the_recipes_for_configs_name_their_sources():
    from services import make_safe

    for stack in ("openssh", "openssl_cnf", "java"):
        rc = make_safe.config_recipe(stack)
        assert rc["summary"] and rc["snippet"] and rc["sources"]
        for src in rc["sources"]:
            assert src["url"].startswith("https://") and src["quote"] and src["checked"]
    assert make_safe.config_recipe("nginx") is None
    assert "openssh" not in make_safe.stack_ids()
