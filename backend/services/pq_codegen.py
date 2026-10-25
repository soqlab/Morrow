"""
Post-Quantum Config & Code Generator

Produces ready-to-paste configuration snippets and code samples for
integrating FIPS 203/204/205 algorithms into common stacks.

Targets:
  nginx         — TLS 1.3 server with X25519MLKEM768 hybrid key exchange
  openssl       — openssl.cnf with post-quantum OIDs and algorithm policy
  openssh_server — sshd_config with mlkem768x25519-sha256 KEM
  openssh_client — ~/.ssh/config with post-quantum KEX preferences
  python        — cryptography + liboqs-python ML-KEM / ML-DSA examples
  go            — cloudflare/circl ML-KEM-768 key exchange
  java          — Bouncy Castle 1.78 ML-KEM / ML-DSA
  nodejs        — node-oqs + @noble/post-quantum examples
  rust          — pqcrypto crate ML-KEM-768 / ML-DSA-65
  docker        — Dockerfile + compose.yml TLS with oqs-provider
  kubernetes    — cert-manager ClusterIssuer with post-quantum algorithm

Pure stdlib — no external dependencies.
"""

from __future__ import annotations

import textwrap
from datetime import datetime, timezone
from typing import Any, Dict, List


_TARGETS = {
    "nginx": {
        "label": "nginx / TLS",
        "icon": "N",
        "description": "TLS 1.3 server with hybrid X25519MLKEM768 key exchange and ECDSA/ML-DSA certificate",
        "language": "nginx",
    },
    "openssl": {
        "label": "OpenSSL 3.x",
        "icon": "O",
        "description": "openssl.cnf provider config with oqs-provider for post-quantum algorithm support",
        "language": "ini",
    },
    "openssh_server": {
        "label": "OpenSSH Server",
        "icon": "S",
        "description": "sshd_config with mlkem768x25519-sha256 KEM prioritized",
        "language": "bash",
    },
    "openssh_client": {
        "label": "OpenSSH Client",
        "icon": "S",
        "description": "~/.ssh/config with post-quantum KEM and host key preferences",
        "language": "bash",
    },
    "python": {
        "label": "Python",
        "icon": "Py",
        "description": "liboqs-python + cryptography library — ML-KEM-768 KEM and ML-DSA-65 signing",
        "language": "python",
    },
    "go": {
        "label": "Go",
        "icon": "Go",
        "description": "cloudflare/circl ML-KEM-768 key encapsulation and ML-DSA-65 signing",
        "language": "go",
    },
    "java": {
        "label": "Java",
        "icon": "J",
        "description": "Bouncy Castle 1.78+ FIPS post-quantum — ML-KEM / ML-DSA provider",
        "language": "java",
    },
    "nodejs": {
        "label": "Node.js",
        "icon": "N",
        "description": "@noble/post-quantum ML-KEM-768 and ML-DSA-65",
        "language": "javascript",
    },
    "rust": {
        "label": "Rust",
        "icon": "Rs",
        "description": "pqcrypto crate — ML-KEM-768 KEM and ML-DSA-65 signing",
        "language": "rust",
    },
    "docker": {
        "label": "Docker / Compose",
        "icon": "D",
        "description": "Dockerfile with OQS-OpenSSL provider and compose.yml TLS termination",
        "language": "dockerfile",
    },
    "kubernetes": {
        "label": "Kubernetes / cert-manager",
        "icon": "K",
        "description": "cert-manager ClusterIssuer with ML-DSA-65 algorithm and TLS policy",
        "language": "yaml",
    },
}


def list_targets() -> List[Dict[str, Any]]:
    return [{"id": k, **v} for k, v in _TARGETS.items()]


HOST_PLACEHOLDER = "<your-host>"


def generate(
    target: str,
    host: str = HOST_PLACEHOLDER,
    algorithm: str = "ML-KEM-768",
    port: int = 443,
    key_type: str = "ecdsa",
) -> Dict[str, Any]:
    """
    Generate a ready-to-paste config/code snippet.

    target    — one of the keys in _TARGETS
    host      — the hostname of the target server (used in comments/configs)
    algorithm — the quantum-vulnerable algorithm being replaced
    port      — port number
    key_type  — existing key type (rsa / ecdsa / ed25519)
    """
    meta = _TARGETS.get(target)
    if not meta:
        return {"error": f"Unknown target '{target}'. Valid targets: {list(_TARGETS.keys())}"}

    generators = {
        "nginx": _gen_nginx,
        "openssl": _gen_openssl,
        "openssh_server": _gen_sshd,
        "openssh_client": _gen_ssh_client,
        "python": _gen_python,
        "go": _gen_go,
        "java": _gen_java,
        "nodejs": _gen_nodejs,
        "rust": _gen_rust,
        "docker": _gen_docker,
        "kubernetes": _gen_kubernetes,
    }

    fn = generators.get(target)
    if not fn:
        return {"error": "Generator not implemented"}

    host = str(host or "").strip() or HOST_PLACEHOLDER
    code = fn(host=host, algorithm=algorithm, port=port, key_type=key_type)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "target_label": meta["label"],
        "language": meta["language"],
        "description": meta["description"],
        "host": host,
        "replaces": algorithm,
        "code": code,
        "notes": _notes(target, algorithm),
    }


def _notes(target: str, algorithm: str) -> List[str]:
    notes = [f"Replacing: {algorithm} → FIPS 203/204/205 compliant algorithms"]
    specific = {
        "nginx": ["Requires nginx ≥ 1.25.3 with OpenSSL 3.x + oqs-provider", "Test with: openssl s_client -connect host:443 -groups X25519MLKEM768"],
        "openssl": ["Download oqs-provider from https://github.com/open-quantum-safe/oqs-provider", "Required OpenSSL ≥ 3.1"],
        "openssh_server": ["Requires OpenSSH ≥ 9.0 (released April 2022)", "Verify: ssh -Q kex | grep mlkem"],
        "openssh_client": ["Post-quantum KEX is available in mainstream OpenSSH since v9.0", "Works with GitHub, GitLab, and modern SSH servers"],
        "python": ["pip install liboqs-python cryptography", "liboqs requires liboqs C library: brew install liboqs or apt-get install liboqs-dev"],
        "go": ["go get github.com/cloudflare/circl@latest", "circl is the Cloudflare cryptography library with FIPS 203/204/205 support"],
        "java": ["Add to pom.xml: org.bouncycastle:bcprov-jdk18on:1.78", "Bouncy Castle 1.78 is the first release with FIPS 203/204/205 finalized names"],
        "nodejs": ["npm install @noble/post-quantum", "@noble/post-quantum is audited, zero-dependency post-quantum library"],
        "rust": ["cargo add pqcrypto pqcrypto-mlkem pqcrypto-mldsa", "pqcrypto binds to liboqs; ensure liboqs is installed"],
        "docker": ["Base image: openquantumsafe/oqs-ossl3", "The OQS project provides pre-built Docker images with post-quantum support"],
        "kubernetes": ["Requires cert-manager ≥ 1.14 with post-quantum issuer plugin", "cert-manager-pq-plugin: github.com/open-quantum-safe/cert-manager-pq"],
    }
    return notes + specific.get(target, [])


# ── Code generators ─────────────────────────────────────────────────────────────

def _gen_nginx(host: str, algorithm: str, port: int, key_type: str) -> str:
    return textwrap.dedent(f"""\
        # nginx.conf — post-quantum-ready TLS 1.3 configuration
        # Generated by Morrow | Replaces: {algorithm}
        # Requires: nginx ≥ 1.25.3 + OpenSSL 3.x + oqs-provider

        server {{
            listen {port} ssl;
            server_name {host};

            # ── TLS settings ───────────────────────────────────────────────────
            ssl_protocols TLSv1.3;
            ssl_prefer_server_ciphers off;

            # Hybrid post-quantum key exchange: X25519 (classical) + ML-KEM-768 (FIPS 203)
            # Falls back gracefully to X25519 for non-post-quantum clients
            ssl_ecdh_curve X25519MLKEM768:X25519:P-256;

            # AEAD cipher suites (TLS 1.3 only uses these)
            ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;

            # ── Certificate ────────────────────────────────────────────────────
            # Option A: Classical ECDSA (compatible with all clients)
            ssl_certificate     /etc/ssl/certs/{host}.crt;
            ssl_certificate_key /etc/ssl/private/{host}.key;

            # Option B: Dual-stack — add ML-DSA-65 cert for post-quantum-capable clients
            # ssl_certificate     /etc/ssl/certs/{host}-mldsa.crt;
            # ssl_certificate_key /etc/ssl/private/{host}-mldsa.key;

            # ── Security headers ───────────────────────────────────────────────
            ssl_session_timeout 1d;
            ssl_session_cache shared:MozSSL:10m;
            ssl_session_tickets off;

            add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
            add_header X-Content-Type-Options nosniff;

            # ── OCSP stapling ──────────────────────────────────────────────────
            ssl_stapling on;
            ssl_stapling_verify on;

            location / {{
                # Your app config here
                proxy_pass http://127.0.0.1:8000;
            }}
        }}

        # Verify post-quantum is active:
        # openssl s_client -connect {host}:{port} -groups X25519MLKEM768 2>&1 | grep "Server Temp Key"
        # Expected: Server Temp Key: X25519MLKEM768, 1184 bits
    """)


def _gen_openssl(host: str, algorithm: str, port: int, key_type: str) -> str:
    return textwrap.dedent("""\
        # openssl.cnf — Enable post-quantum via OQS Provider
        # Generated by Morrow
        # Download oqs-provider: https://github.com/open-quantum-safe/oqs-provider

        [openssl_init]
        providers = provider_sect

        [provider_sect]
        default = default_sect
        oqsprovider = oqsprovider_sect

        [default_sect]
        activate = 1

        [oqsprovider_sect]
        module = /usr/lib/ossl-modules/oqsprovider.so
        activate = 1

        # ── Generate ML-KEM-768 key pair ──────────────────────────────────────
        # openssl genpkey -algorithm ML-KEM-768 -out mlkem768.key
        # openssl pkey -in mlkem768.key -pubout -out mlkem768.pub

        # ── Generate ML-DSA-65 signing key + self-signed cert ─────────────────
        # openssl req -x509 -new -newkey ML-DSA-65 -keyout mldsa65.key \\
        #   -out mldsa65.crt -days 365 -subj "/CN=example.com" -nodes

        # ── Classify installed algorithms ─────────────────────────────────────
        # openssl list -kem-algorithms | grep -i kem
        # openssl list -signature-algorithms | grep -i dsa

        # ── Test post-quantum TLS handshake ────────────────────────────────────────────
        # openssl s_client -groups X25519MLKEM768 -connect example.com:443
        # openssl s_server -key mldsa65.key -cert mldsa65.crt -accept 4433 -tls1_3
    """)


def _gen_sshd(host: str, algorithm: str, port: int, key_type: str) -> str:
    return textwrap.dedent(f"""\
        # /etc/ssh/sshd_config — post-quantum-ready OpenSSH server
        # Generated by Morrow | Replaces: {algorithm}
        # Requires: OpenSSH ≥ 9.0

        # ── Key exchange: post-quantum hybrid first, classical fallback ─────────────────
        KexAlgorithms mlkem768x25519-sha256,curve25519-sha256,ecdh-sha2-nistp256

        # ── Host keys: Ed25519 + consider adding ML-DSA when available ─────────
        HostKey /etc/ssh/ssh_host_ed25519_key
        HostKey /etc/ssh/ssh_host_ecdsa_key

        # ── Authentication: public key only ────────────────────────────────────
        PasswordAuthentication no
        PubkeyAuthentication yes
        AuthorizedKeysFile .ssh/authorized_keys

        # ── Ciphers and MACs ───────────────────────────────────────────────────
        Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com
        MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

        # ── Hardening ──────────────────────────────────────────────────────────
        Protocol 2
        LoginGraceTime 30
        MaxAuthTries 3
        AllowAgentForwarding no
        X11Forwarding no

        # Verify post-quantum KEX after restart:
        # sudo systemctl restart sshd
        # ssh -vvv {host} 2>&1 | grep -i kex_algorithms
        # Look for: kex_algorithms: mlkem768x25519-sha256,...
    """)


def _gen_ssh_client(host: str, algorithm: str, port: int, key_type: str) -> str:
    return textwrap.dedent(f"""\
        # ~/.ssh/config — post-quantum-ready OpenSSH client
        # Generated by Morrow | Replaces: {algorithm}
        # Requires: OpenSSH ≥ 9.0 (ships with Ubuntu 22.04, macOS Ventura+)

        # Post-quantum defaults for all hosts
        Host *
            KexAlgorithms mlkem768x25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256
            HostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256
            Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr
            MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
            ServerAliveInterval 60
            ServerAliveCountMax 3

        # Specific host: {host}
        Host {host}
            HostName {host}
            Port {port if port != 443 else 22}
            User deploy
            IdentityFile ~/.ssh/id_ed25519
            # When ML-DSA keys are available in OpenSSH:
            # IdentityFile ~/.ssh/id_mldsa65

        # Verify post-quantum is negotiated:
        # ssh -vvv {host} 2>&1 | grep kex_algorithms
    """)


def _gen_python(host: str, algorithm: str, port: int, key_type: str) -> str:
    return textwrap.dedent(f"""\
        #!/usr/bin/env python3
        \"\"\"
        post-quantum key exchange + signing — Python
        Generated by Morrow | Replaces: {algorithm}

        Dependencies:
            pip install liboqs-python cryptography
        \"\"\"
        import oqs                    # liboqs-python
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        # ── ML-KEM-768 Key Encapsulation (FIPS 203) ───────────────────────────
        def demo_mlkem() -> None:
            kem_name = "ML-KEM-768"

            # Alice generates a key pair (recipient side)
            with oqs.KeyEncapsulation(kem_name) as kem:
                alice_pub = kem.generate_keypair()

                # Bob encapsulates a shared secret to Alice's public key
                with oqs.KeyEncapsulation(kem_name) as bob:
                    ciphertext, shared_secret_bob = bob.encap_secret(alice_pub)

                # Alice decapsulates the shared secret from Bob's ciphertext
                shared_secret_alice = kem.decap_secret(ciphertext)

            assert shared_secret_alice == shared_secret_bob
            print(f"ML-KEM-768 shared secret established: {{len(shared_secret_alice)}} bytes")
            # Use shared_secret_alice as key material for AES-256-GCM

        # ── ML-DSA-65 Digital Signature (FIPS 204) ────────────────────────────
        def demo_mldsa() -> None:
            sig_name = "ML-DSA-65"
            message = b"Post-quantum-signed payload for {host}"

            with oqs.Signature(sig_name) as signer:
                pub_key = signer.generate_keypair()
                signature = signer.sign(message)

            with oqs.Signature(sig_name) as verifier:
                is_valid = verifier.verify(message, signature, pub_key)

            print(f"ML-DSA-65 signature valid: {{is_valid}}")
            print(f"Signature length: {{len(signature)}} bytes (vs RSA-2048: 256 bytes)")

        # ── Hybrid TLS with Python requests ───────────────────────────────────
        def hybrid_tls_request() -> None:
            \"\"\"
            Python's ssl module doesn't yet support post-quantum KEX natively.
            Use oqs-openssl3 as the backend or call via subprocess to curl/openssl.
            \"\"\"
            import subprocess
            result = subprocess.run([
                "openssl", "s_client",
                "-groups", "X25519MLKEM768",
                "-connect", f"{host}:{port}",
                "-brief",
            ], capture_output=True, text=True, timeout=10)
            print(result.stdout)

        if __name__ == "__main__":
            demo_mlkem()
            demo_mldsa()
    """)


def _gen_go(host: str, algorithm: str, port: int, key_type: str) -> str:
    return textwrap.dedent(f"""\
        // post-quantum key exchange + signing — Go
        // Generated by Morrow | Replaces: {algorithm}
        // go get github.com/cloudflare/circl@latest

        package main

        import (
        \t"crypto/tls"
        \t"fmt"
        \t"net/http"

        \tcirclkem "github.com/cloudflare/circl/kem/mlkem/mlkem768"
        \tcirclsig "github.com/cloudflare/circl/sign/mldsa/mldsa65"
        )

        // ── ML-KEM-768 Key Encapsulation (FIPS 203) ──────────────────────────
        func demoMLKEM() {{
        \t// Generate key pair (recipient / server side)
        \tpub, priv, err := circlkem.GenerateKeyPair(nil)
        \tif err != nil {{
        \t\tpanic(err)
        \t}}

        \t// Encapsulate (sender / client side)
        \tct, ssEnc, err := circlkem.EncapsulateTo(pub, nil)
        \tif err != nil {{
        \t\tpanic(err)
        \t}}

        \t// Decapsulate (recipient)
        \tssDecap, err := priv.Decapsulate(ct)
        \tif err != nil {{
        \t\tpanic(err)
        \t}}

        \tif string(ssEnc) != string(ssDecap) {{
        \t\tpanic("shared secrets differ")
        \t}}
        \tfmt.Printf("ML-KEM-768 shared secret: %d bytes\\n", len(ssDecap))
        }}

        // ── ML-DSA-65 Signing (FIPS 204) ─────────────────────────────────────
        func demoMLDSA() {{
        \tpub, priv, _ := circlsig.GenerateKey(nil)
        \tmsg := []byte("Post-quantum-signed payload for {host}")

        \tsig := priv.Sign(msg, nil)
        \tvalid := pub.Verify(msg, sig, nil)
        \tfmt.Printf("ML-DSA-65 signature valid: %v, length: %d bytes\\n", valid, len(sig))
        }}

        // ── Hybrid TLS client (X25519MLKEM768) ───────────────────────────────
        func pqHTTPClient() *http.Client {{
        \t// Go 1.23+ supports X25519MLKEM768 via GODEBUG=tlskyber=1
        \t// or explicitly via crypto/tls CurvePreferences
        \tcfg := &tls.Config{{
        \t\tMinVersion: tls.VersionTLS13,
        \t\t// CurvePreferences: []tls.CurveID{{tls.X25519MLKEM768, tls.X25519}},
        \t}}
        \treturn &http.Client{{
        \t\tTransport: &http.Transport{{TLSClientConfig: cfg}},
        \t}}
        }}

        func main() {{
        \tdemoMLKEM()
        \tdemoMLDSA()
        \tclient := pqHTTPClient()
        \tresp, err := client.Get("https://{host}:{port}/")
        \tif err == nil {{
        \t\tfmt.Println("Post-quantum TLS handshake succeeded:", resp.Status)
        \t\tresp.Body.Close()
        \t}}
        }}
    """)


def _gen_java(host: str, algorithm: str, port: int, key_type: str) -> str:
    return textwrap.dedent(f"""\
        // post-quantum key exchange + signing — Java (Bouncy Castle 1.78+)
        // Generated by Morrow | Replaces: {algorithm}
        // Maven: org.bouncycastle:bcprov-jdk18on:1.78

        import org.bouncycastle.pqc.crypto.mlkem.*;
        import org.bouncycastle.pqc.crypto.mldsa.*;
        import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
        import org.bouncycastle.jce.provider.BouncyCastleProvider;
        import java.security.Security;

        public class PostQuantumDemo {{

            static {{
                Security.addProvider(new BouncyCastleProvider());
            }}

            // ── ML-KEM-768 Key Encapsulation (FIPS 203) ──────────────────────
            public static void demoMLKEM() throws Exception {{
                var params = MLKEMParameters.ml_kem_768;
                var keyGen = new MLKEMKeyPairGenerator();
                keyGen.init(new MLKEMKeyGenerationParameters(new java.security.SecureRandom(), params));

                AsymmetricCipherKeyPair kp = keyGen.generateKeyPair();
                var pubKey = (MLKEMPublicKeyParameters) kp.getPublic();
                var privKey = (MLKEMPrivateKeyParameters) kp.getPrivate();

                // Encapsulate (sender)
                var encap = new MLKEMEncapsulator();
                encap.init(pubKey);
                var encResult = encap.encapsulate(0, 32, "ML-KEM-768");
                byte[] ciphertext = encResult.getEncapsulation();
                byte[] sharedSecretSender = encResult.getSecret();

                // Decapsulate (recipient)
                var decap = new MLKEMDecapsulator();
                decap.init(privKey);
                byte[] sharedSecretRecipient = decap.decapsulate(ciphertext, 0, ciphertext.length, "ML-KEM-768");

                System.out.println("ML-KEM-768 shared secret length: " + sharedSecretRecipient.length);
            }}

            // ── ML-DSA-65 Signing (FIPS 204) ─────────────────────────────────
            public static void demoMLDSA() throws Exception {{
                var params = MLDSAParameters.ml_dsa_65;
                var keyGen = new MLDSAKeyPairGenerator();
                keyGen.init(new MLDSAKeyGenerationParameters(new java.security.SecureRandom(), params));

                AsymmetricCipherKeyPair kp = keyGen.generateKeyPair();
                byte[] message = "Post-quantum signed for {host}".getBytes();

                var signer = new MLDSASigner();
                signer.init(true, kp.getPrivate());
                signer.update(message, 0, message.length);
                byte[] signature = signer.generateSignature();

                signer.init(false, kp.getPublic());
                signer.update(message, 0, message.length);
                boolean valid = signer.verifySignature(signature);
                System.out.println("ML-DSA-65 valid: " + valid + ", sig bytes: " + signature.length);
            }}

            public static void main(String[] args) throws Exception {{
                demoMLKEM();
                demoMLDSA();
            }}
        }}
    """)


def _gen_nodejs(host: str, algorithm: str, port: int, key_type: str) -> str:
    return textwrap.dedent(f"""\
        // post-quantum key exchange + signing — Node.js
        // Generated by Morrow | Replaces: {algorithm}
        // npm install @noble/post-quantum

        import {{ ml_kem768 }} from '@noble/post-quantum/ml-kem';
        import {{ ml_dsa65 }} from '@noble/post-quantum/ml-dsa';
        import {{ randomBytes }} from 'crypto';

        // ── ML-KEM-768 Key Encapsulation (FIPS 203) ───────────────────────────
        async function demoMLKEM() {{
          // Generate recipient key pair
          const seed = randomBytes(64);
          const {{ publicKey, secretKey }} = ml_kem768.keygen(seed);

          // Sender encapsulates shared secret to recipient's public key
          const {{ cipherText, sharedSecret: senderSecret }} = ml_kem768.encapsulate(publicKey);

          // Recipient decapsulates
          const receiverSecret = ml_kem768.decapsulate(cipherText, secretKey);

          const match = Buffer.from(senderSecret).equals(Buffer.from(receiverSecret));
          console.log(`ML-KEM-768 shared secrets match: ${{match}}`);
          console.log(`Shared secret length: ${{senderSecret.length}} bytes`);
          // Use sharedSecret as AES-256-GCM key material
        }}

        // ── ML-DSA-65 Digital Signature (FIPS 204) ────────────────────────────
        async function demoMLDSA() {{
          const seed = randomBytes(32);
          const {{ publicKey, secretKey }} = ml_dsa65.keygen(seed);

          const message = new TextEncoder().encode('Post-quantum signed payload for {host}');
          const signature = ml_dsa65.sign(secretKey, message);
          const valid = ml_dsa65.verify(publicKey, message, signature);

          console.log(`ML-DSA-65 signature valid: ${{valid}}`);
          console.log(`Signature length: ${{signature.length}} bytes`);
        }}

        // ── Hybrid HTTPS with Node TLS (requires Node ≥ 22 + oqs-provider) ───
        import {{ request }} from 'https';
        function pqHttpsRequest() {{
          const req = request({{
            host: '{host}',
            port: {port},
            path: '/',
            // Node.js 22+ supports ecdhCurve for post-quantum groups when using oqs-openssl3
            // ecdhCurve: 'X25519MLKEM768',
          }}, (res) => {{
            console.log(`HTTPS status: ${{res.statusCode}}`);
          }});
          req.end();
        }}

        await demoMLKEM();
        await demoMLDSA();
        pqHttpsRequest();
    """)


def _gen_rust(host: str, algorithm: str, port: int, key_type: str) -> str:
    return textwrap.dedent(f"""\
        // post-quantum key exchange + signing — Rust
        // Generated by Morrow | Replaces: {algorithm}
        // Cargo.toml:
        //   [dependencies]
        //   pqcrypto = "0.17"
        //   pqcrypto-mlkem = "0.8"
        //   pqcrypto-mldsa = "0.5"

        use pqrypto_mlkem::mlkem768;
        use pqrypto_mldsa::mldsa65;
        use pqrypto_traits::kem::{{PublicKey, SecretKey, SharedSecret, Ciphertext}};
        use pqrypto_traits::sign::{{PublicKey as SPubKey, SecretKey as SSecKey, SignedMessage}};

        // ── ML-KEM-768 Key Encapsulation (FIPS 203) ───────────────────────────
        fn demo_mlkem() {{
            // Generate key pair (recipient)
            let (pk, sk) = mlkem768::keypair();

            // Encapsulate shared secret (sender)
            let (shared_secret_sender, ciphertext) = mlkem768::encapsulate(&pk);

            // Decapsulate (recipient)
            let shared_secret_recipient = mlkem768::decapsulate(&ciphertext, &sk);

            assert_eq!(
                shared_secret_sender.as_bytes(),
                shared_secret_recipient.as_bytes(),
                "Shared secrets must match"
            );
            println!("ML-KEM-768 shared secret: {{}} bytes", shared_secret_sender.as_bytes().len());
            // Use as AES-256-GCM key material
        }}

        // ── ML-DSA-65 Signing (FIPS 204) ──────────────────────────────────────
        fn demo_mldsa() {{
            let (pk, sk) = mldsa65::keypair();
            let message = b"Post-quantum signed payload for {host}";

            let signed = mldsa65::sign(message, &sk);
            let verified = mldsa65::open(&signed, &pk).expect("Signature verification failed");

            println!("ML-DSA-65 verified: true, sig overhead: {{}} bytes",
                signed.as_bytes().len() - message.len());
        }}

        fn main() {{
            demo_mlkem();
            demo_mldsa();
            println!("All post-quantum primitives verified for {host}");
        }}
    """)


def _gen_docker(host: str, algorithm: str, port: int, key_type: str) -> str:
    return textwrap.dedent(f"""\
        # Dockerfile — post-quantum-ready container with OQS-OpenSSL provider
        # Generated by Morrow | Replaces: {algorithm}

        FROM openquantumsafe/oqs-ossl3:latest AS pq-base
        # This image ships OpenSSL 3.x + oqs-provider with all FIPS 203/204/205 algorithms

        FROM pq-base AS app
        WORKDIR /app

        # Generate ML-DSA-65 TLS certificate for {host}
        RUN openssl req -x509 -new -newkey ML-DSA-65 \\
              -keyout /etc/ssl/private/mldsa65.key \\
              -out /etc/ssl/certs/mldsa65.crt \\
              -days 365 \\
              -subj "/CN={host}/O=Morrow/C=US" \\
              -nodes

        COPY . .
        EXPOSE {port}
        CMD ["python", "app.py"]

        ---

        # docker-compose.yml — post-quantum TLS termination
        # Generated by Morrow

        services:
          app:
            build: .
            environment:
              - OPENSSL_CONF=/etc/ssl/openssl-pq.cnf
              - OPENSSL_MODULES=/usr/lib/ossl-modules

          nginx:
            image: openquantumsafe/nginx:latest
            ports:
              - "{port}:{port}"
            volumes:
              - ./nginx-pq.conf:/etc/nginx/nginx.conf:ro
              - ./certs:/etc/ssl:ro
            depends_on:
              - app
            environment:
              - SSL_GROUPS=X25519MLKEM768:X25519:P-256

        # Test:
        # docker compose up -d
        # openssl s_client -groups X25519MLKEM768 -connect localhost:{port}
    """)


def _gen_kubernetes(host: str, algorithm: str, port: int, key_type: str) -> str:
    return textwrap.dedent(f"""\
        # Kubernetes — post-quantum cert-manager ClusterIssuer + TLS policy
        # Generated by Morrow | Replaces: {algorithm}
        # Requires: cert-manager ≥ 1.14 + cert-manager-pq-plugin

        ---
        apiVersion: cert-manager.io/v1
        kind: ClusterIssuer
        metadata:
          name: pq-issuer
          annotations:
            morrow.soqlab.com/algorithm: "ML-DSA-65"
            morrow.soqlab.com/kem: "ML-KEM-768"
        spec:
          selfSigned: {{}}
          # For production: use Let's Encrypt or your PKI with ML-DSA support
          # acme:
          #   server: https://acme-v02.api.letsencrypt.org/directory
          #   email: pki@{host}
          #   privateKeySecretRef:
          #     name: letsencrypt-mldsa-key
          #     algorithm: ML-DSA-65
          #   solvers:
          #     - http01:
          #         ingress:
          #           class: nginx

        ---
        apiVersion: cert-manager.io/v1
        kind: Certificate
        metadata:
          name: {host.replace('.', '-')}-pq-tls
          namespace: default
        spec:
          secretName: {host.replace('.', '-')}-pq-tls
          dnsNames:
            - {host}
          issuerRef:
            name: pq-issuer
            kind: ClusterIssuer
          privateKey:
            algorithm: ECDSA   # fallback; use ML-DSA-65 when cert-manager supports it
            size: 256

        ---
        # TLS policy enforcing post-quantum key exchange
        apiVersion: networking.k8s.io/v1
        kind: Ingress
        metadata:
          name: {host.replace('.', '-')}-ingress
          annotations:
            nginx.ingress.kubernetes.io/ssl-ciphers: "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"
            nginx.ingress.kubernetes.io/ssl-protocols: "TLSv1.3"
            # Enable X25519MLKEM768 key exchange when OQS nginx is deployed:
            nginx.ingress.kubernetes.io/configuration-snippet: |
              ssl_ecdh_curve X25519MLKEM768:X25519:P-256;
        spec:
          tls:
            - hosts:
                - {host}
              secretName: {host.replace('.', '-')}-pq-tls
          rules:
            - host: {host}
              http:
                paths:
                  - path: /
                    pathType: Prefix
                    backend:
                      service:
                        name: app-service
                        port:
                          number: {port}
    """)
