"""Exercise the built Linux image and real HAProxy without customer DNS or origin traffic."""
from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import secrets
import shutil
import ssl
import subprocess
import tempfile
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def docker(*args):
    result = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=90, check=False)
    if result.returncode:
        raise RuntimeError(f"Docker operation failed: {args[0]}: {result.stderr[:1500]}")
    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="airlock-website-gateway:local-check")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    scratch = root / ".tools"
    scratch.mkdir(exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="gateway-runtime-test-", dir=scratch)).resolve()
    prefix = "gateway-test-" + secrets.token_hex(5)
    containers, network_created = [], False
    try:
        for part in ("state", "secrets", "certs"):
            (work / part).mkdir(mode=0o700)
        secret = secrets.token_hex(32)
        policy = {"site_id": "b" * 32, "hostname": "shop.customer.com", "origin_url": "https://origin.customer.com",
                  "version": 1, "mode": "observe", "exceptions": [], "retention_hours": 24, "max_body_bytes": 1048576}
        (work / "state/policy.json").write_bytes(canonical(policy))
        (work / "secrets/gateway.secret").write_text(secret, encoding="ascii")
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Airlock local test only")])
        now = datetime.datetime.now(datetime.timezone.utc)
        certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(private.public_key())
                       .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=1))
                       .not_valid_after(now + datetime.timedelta(hours=1))
                       .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                       .add_extension(x509.SubjectAlternativeName([x509.DNSName(policy["hostname"]), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
                       .sign(private, hashes.SHA256()))
        (work / "certs/fullchain.pem").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        (work / "certs/privkey.pem").write_bytes(private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        for file in work.glob("*/*"):
            file.chmod(0o600)
        tls = ssl.create_default_context(cafile=str(work / "certs/fullchain.pem"))
        docker("network", "create", prefix)
        network_created = True
        uid = str(os.getuid()) if hasattr(os, "getuid") else "10001"
        for replica in ("a", "b"):
            container = prefix + "-" + replica
            docker("run", "-d", "--name", container, "--network", prefix, "--network-alias", "gateway-" + replica,
                   "--user", uid, "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                   "--memory", "768m", "--cpus", "1", "--tmpfs", "/tmp:size=16m,mode=1777",
                   "-e", "GOMEMLIMIT=512MiB", "-e", "GOMAXPROCS=2", "-e", "HOSTNAME=" + replica,
                   "-v", f"{work / 'state'}:/state", "-v", f"{work / 'secrets'}:/secrets:ro", "-v", f"{work / 'certs'}:/certs:ro", args.image)
            containers.append(container)
        edge = prefix + "-edge"
        docker("run", "-d", "--name", edge, "--network", prefix, "--read-only", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges:true", "-p", "127.0.0.1::8443",
               "-v", f"{root / 'gateway/haproxy.cfg'}:/usr/local/etc/haproxy/haproxy.cfg:ro", "haproxy:3.2-alpine")
        containers.append(edge)
        port = int(docker("port", edge, "8443").rsplit(":", 1)[1])

        def request(path, method="GET", body=None, authorized=False):
            connection = http.client.HTTPSConnection("127.0.0.1", port, context=tls, timeout=5)
            try:
                headers = {"Host": policy["hostname"]}
                if authorized:
                    headers["Authorization"] = "Bearer " + secret
                if body is not None:
                    headers["Content-Type"] = "application/json"
                connection.request(method, path, body=body, headers=headers)
                response = connection.getresponse()
                return response.status, response.read(65536)
            finally:
                connection.close()

        def challenge():
            nonce = secrets.token_hex(24)
            status, body = request("/__airlock/challenge?nonce=" + nonce)
            assert status == 200
            envelope = json.loads(body)
            raw = base64.b64decode(envelope["payload"], validate=True)
            assert hmac.compare_digest(envelope["signature"], hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest())
            data = json.loads(raw)
            assert data["nonce"] == nonce and data["site_id"] == policy["site_id"] and abs(time.time() - data["time"]) < 60
            assert data["waf_self_test"] is True
            return data

        def converged(expected, instances, stable_samples=1):
            seen, streak, deadline = set(), 0, time.monotonic() + 40
            while time.monotonic() < deadline:
                try:
                    data = challenge()
                    if data["config_hash"] == hashlib.sha256(canonical(expected)).hexdigest() and data["mode"] == expected["mode"]:
                        seen.add(data["instance"])
                        streak += 1
                    else:
                        streak = 0
                    if seen >= instances and streak >= stable_samples:
                        return
                except (OSError, http.client.HTTPException, ValueError, AssertionError):
                    streak = 0
                time.sleep(0.4)
            raise AssertionError("Real gateway replicas did not converge to the expected signed policy")

        converged(policy, {"a", "b"})
        assert request("/__airlock/statistics")[0] == 401
        policy.update(version=2, mode="enforce")
        assert request("/__airlock/policy", "PUT", canonical(policy), True)[0] == 200
        converged(policy, {"a", "b"})
        for _ in range(4):
            # A WAF interruption proves this request never reaches the configured origin.
            assert request("/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")[0] == 403
        status, body = request("/__airlock/statistics", authorized=True)
        stats = json.loads(body)
        assert status == 200 and stats["blocked"] > 0 and stats["matched"] > 0
        assert stats["config_hash"] == hashlib.sha256(canonical(policy)).hexdigest()
        assert request("/__airlock/policy", "PUT", b'{"broken":true}', True)[0] == 409
        converged(policy, {"a", "b"})
        policy.update(version=3, mode="observe")
        assert request("/__airlock/policy", "PUT", canonical(policy), True)[0] == 200
        converged(policy, {"a", "b"})
        docker("stop", prefix + "-a")
        converged(policy, {"b"}, stable_samples=8)
        for _ in range(4):
            assert challenge()["instance"] == "b"
        docker("stop", prefix + "-b")
        try:
            request("/__airlock/challenge?nonce=" + secrets.token_hex(24))
        except (OSError, http.client.HTTPException):
            pass
        else:
            raise AssertionError("Edge did not fail closed when both replicas stopped")
        docker("start", prefix + "-b")
        converged(policy, {"b"})
        print("PASS: built non-root image, verified TLS, Python/Go HMAC and policy hashes, real WAF blocking, replica convergence, rollback, restart persistence, HAProxy failover and fail-closed outage.")
    finally:
        for name in reversed(containers):
            docker("rm", "-f", name)
        if network_created:
            docker("network", "rm", prefix)
        # Resolve and bound the recursive cleanup before deleting only our generated fixtures.
        if work.parent != scratch.resolve() or not work.name.startswith("gateway-runtime-test-"):
            raise RuntimeError("Refusing cleanup outside the generated test workspace")
        shutil.rmtree(work)


if __name__ == "__main__":
    main()
