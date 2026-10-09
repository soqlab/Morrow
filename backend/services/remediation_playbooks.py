"""
Remediation Playbooks

Pre-built, step-by-step PQC migration guides per technology stack.
Each playbook contains:
  - Prerequisites check
  - Ordered steps with copy-paste config/code snippets
  - Verification commands
  - Per-asset checklist tracking persisted in DB

Tables created: playbook_progress
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from db_feature_store import feature_conn


# ── Static playbook library ────────────────────────────────────────────────────

_PLAYBOOKS: Dict[str, Dict[str, Any]] = {
    "nginx": {
        "id": "nginx",
        "name": "nginx / OpenSSL TLS Upgrade",
        "description": "Upgrade nginx to support hybrid PQC key exchange (X25519Kyber768) and restrict legacy cipher suites.",
        "stack": "nginx",
        "difficulty": "medium",
        "estimated_time": "2–4 hours",
        "prerequisites": [
            "nginx >= 1.25.0 or nginx-quic",
            "OpenSSL >= 3.2 with liboqs provider, OR BoringSSL with Kyber support",
            "Root / sudo access to the web server",
        ],
        "steps": [
            {
                "id": 1,
                "title": "Install OpenSSL 3.2+ with OQS provider",
                "description": "Build or install the open-quantum-safe (OQS) provider so OpenSSL exposes Kyber KEM groups.",
                "snippet": (
                    "# Ubuntu/Debian\n"
                    "sudo apt-get install -y cmake ninja-build\n"
                    "git clone --depth 1 https://github.com/open-quantum-safe/oqs-provider.git\n"
                    "cd oqs-provider && cmake -GNinja -DBUILD_SHARED_LIBS=ON . && ninja\n"
                    "sudo cp _build/lib/oqsprovider.so $(openssl version -d | cut -d'\"' -f2)/ossl-modules/\n"
                    "# Append to /etc/ssl/openssl.cnf\n"
                    "[openssl_init]\n"
                    "providers = provider_sect\n"
                    "[provider_sect]\n"
                    "default = default_sect\n"
                    "oqsprovider = oqs_sect\n"
                    "[oqs_sect]\n"
                    "activate = 1"
                ),
                "verification": "openssl list -providers | grep oqsprovider",
            },
            {
                "id": 2,
                "title": "Build nginx with OpenSSL 3.2 + OQS",
                "description": "Recompile nginx to link against your OQS-enabled OpenSSL (or use a pre-built package).",
                "snippet": (
                    "./configure --with-openssl=/path/to/openssl-3.2 \\\n"
                    "  --with-openssl-opt='enable-tls1_3' \\\n"
                    "  --with-http_ssl_module --with-http_v2_module\n"
                    "make -j$(nproc) && sudo make install"
                ),
                "verification": "nginx -V 2>&1 | grep OpenSSL",
            },
            {
                "id": 3,
                "title": "Configure hybrid PQC cipher suite",
                "description": "Enable X25519Kyber768 hybrid group in nginx.conf for forward-secret PQC key exchange.",
                "snippet": (
                    "# /etc/nginx/nginx.conf (or site config)\n"
                    "ssl_protocols TLSv1.3;\n"
                    "ssl_prefer_server_ciphers off;\n"
                    "ssl_ecdh_curve X25519Kyber768:X25519:prime256v1;\n"
                    "ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;\n"
                    "ssl_session_timeout 1d;\n"
                    "ssl_session_cache shared:SSL:50m;\n"
                    "add_header Strict-Transport-Security 'max-age=63072000' always;"
                ),
                "verification": "nginx -t && sudo systemctl reload nginx",
            },
            {
                "id": 4,
                "title": "Disable legacy / vulnerable cipher suites",
                "description": "Remove RSA key exchange, DH < 2048, and RC4/3DES from the allowed list.",
                "snippet": (
                    "# Add to ssl_ciphers (nginx TLS 1.2 fallback, if needed)\n"
                    "ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';\n"
                    "# Explicitly deny weak suites (OpenSSL syntax)\n"
                    "ssl_ciphers '!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!3DES';"
                ),
                "verification": "openssl s_client -connect localhost:443 -tls1_2 -cipher 'RC4' && echo FAIL || echo OK (connection refused = good)",
            },
            {
                "id": 5,
                "title": "Verify hybrid PQC handshake",
                "description": "Confirm a client negotiates X25519Kyber768 during the TLS 1.3 handshake.",
                "snippet": (
                    "# Using oqs-openssl client\n"
                    "openssl s_client -connect localhost:443 -curves X25519Kyber768 -tls1_3\n"
                    "# Look for: Server Temp Key: X25519Kyber768\n\n"
                    "# Or with curl (if built with OQS)\n"
                    "curl -v --curves X25519Kyber768 https://localhost/"
                ),
                "verification": "openssl s_client -connect localhost:443 2>&1 | grep 'Server Temp Key'",
            },
        ],
    },
    "openssl": {
        "id": "openssl",
        "name": "OpenSSL Library Migration",
        "description": "Upgrade applications using OpenSSL directly to use ML-KEM / ML-DSA via the OQS provider or liboqs bindings.",
        "stack": "openssl",
        "difficulty": "hard",
        "estimated_time": "4–8 hours",
        "prerequisites": [
            "OpenSSL >= 3.0 in your application",
            "Access to source code",
            "liboqs or oqs-provider installed",
        ],
        "steps": [
            {
                "id": 1,
                "title": "Inventory all OpenSSL API calls",
                "description": "Find every use of RSA_generate_key, EC_KEY_new_by_curve_name, EVP_DigestSign, etc.",
                "snippet": (
                    "# Grep for vulnerable patterns\n"
                    "grep -rn 'RSA_generate_key\\|EC_KEY_new\\|EVP_PKEY_RSA\\|NID_X9_62' src/ --include='*.c' --include='*.h'\n"
                    "grep -rn 'RSA\\|ECDSA\\|ECDH' src/ --include='*.py' --include='*.go'"
                ),
                "verification": "Review output — each hit is a migration candidate.",
            },
            {
                "id": 2,
                "title": "Replace RSA key generation with ML-DSA (signing)",
                "description": "Use EVP_PKEY_CTX with the OQS provider to generate ML-DSA-65 keys.",
                "snippet": (
                    "// C — ML-DSA-65 key generation\n"
                    "EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, \"mldsa65\", NULL);\n"
                    "EVP_PKEY_keygen_init(ctx);\n"
                    "EVP_PKEY *pkey = NULL;\n"
                    "EVP_PKEY_generate(ctx, &pkey);\n\n"
                    "# Python (via cryptography >= 44 or oqs-python)\n"
                    "import oqs\n"
                    "signer = oqs.Signature('Dilithium3')  # ML-DSA-65\n"
                    "pub = signer.generate_keypair()\n"
                    "sig = signer.sign(b'message')"
                ),
                "verification": "Unit test: sign + verify with ML-DSA-65 key pair.",
            },
            {
                "id": 3,
                "title": "Replace ECDH key exchange with ML-KEM-768",
                "description": "Use EVP_PKEY_CTX with 'mlkem768' to encapsulate/decapsulate shared secrets.",
                "snippet": (
                    "// C — ML-KEM-768 encapsulation\n"
                    "EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, \"mlkem768\", NULL);\n"
                    "EVP_PKEY_keygen_init(ctx);\n"
                    "EVP_PKEY *kem_key = NULL;\n"
                    "EVP_PKEY_generate(ctx, &kem_key);\n\n"
                    "# Python\n"
                    "import oqs\n"
                    "kem = oqs.KeyEncapsulation('Kyber768')  # ML-KEM-768\n"
                    "pub = kem.generate_keypair()\n"
                    "ciphertext, shared_secret = kem.encap_secret(pub)"
                ),
                "verification": "Test: encap on sender, decap on receiver — shared secrets must match.",
            },
            {
                "id": 4,
                "title": "Update certificate generation to hybrid",
                "description": "Issue X.509 certificates with a hybrid RSA+ML-DSA or ECDSA+ML-DSA signature scheme.",
                "snippet": (
                    "# Generate hybrid ML-DSA-65 certificate via OpenSSL CLI\n"
                    "openssl genpkey -algorithm mldsa65 -out server-pqc.key\n"
                    "openssl req -new -key server-pqc.key -out server-pqc.csr \\\n"
                    "  -subj '/CN=myserver.example.com/O=MyOrg'\n"
                    "openssl x509 -req -in server-pqc.csr -signkey server-pqc.key \\\n"
                    "  -out server-pqc.crt -days 825"
                ),
                "verification": "openssl x509 -in server-pqc.crt -text | grep 'Public Key Algorithm'",
            },
        ],
    },
    "java": {
        "id": "java",
        "name": "Java / JVM PQC Migration",
        "description": "Migrate Java applications using JCA/JCE or Bouncy Castle to ML-KEM and ML-DSA.",
        "stack": "java",
        "difficulty": "medium",
        "estimated_time": "3–6 hours",
        "prerequisites": [
            "Java 17+ (Java 21 recommended for Virtual Threads)",
            "Bouncy Castle >= 1.77 (includes PQC provider) or JDK 21+ with OQS PKCS#11 bridge",
            "Maven or Gradle build system",
        ],
        "steps": [
            {
                "id": 1,
                "title": "Add Bouncy Castle PQC provider",
                "description": "Include the bcprov-jdk18on and bcpqc-jdk18on artifacts in your build.",
                "snippet": (
                    "<!-- Maven pom.xml -->\n"
                    "<dependency>\n"
                    "  <groupId>org.bouncycastle</groupId>\n"
                    "  <artifactId>bcprov-jdk18on</artifactId>\n"
                    "  <version>1.78.1</version>\n"
                    "</dependency>\n"
                    "<dependency>\n"
                    "  <groupId>org.bouncycastle</groupId>\n"
                    "  <artifactId>bcpqc-jdk18on</artifactId>\n"
                    "  <version>1.78.1</version>\n"
                    "</dependency>\n\n"
                    "// Register provider at startup\n"
                    "Security.addProvider(new BouncyCastleProvider());\n"
                    "Security.addProvider(new BouncyCastlePQCProvider());"
                ),
                "verification": "Security.getProvider(\"BCPQC\") != null",
            },
            {
                "id": 2,
                "title": "Replace RSA encryption with ML-KEM-768",
                "description": "Use the BCPQC KEM API for key encapsulation in place of RSA OAEP.",
                "snippet": (
                    "import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;\n\n"
                    "// Key generation\n"
                    "KeyPairGenerator kpg = KeyPairGenerator.getInstance(\"Kyber\", \"BCPQC\");\n"
                    "kpg.initialize(KyberParameterSpec.kyber768, new SecureRandom());\n"
                    "KeyPair kp = kpg.generateKeyPair();\n\n"
                    "// Encapsulation (sender)\n"
                    "KeyGenerator kg = KeyGenerator.getInstance(\"Kyber\", \"BCPQC\");\n"
                    "kg.init(new KEMGenerateSpec(kp.getPublic(), \"AES\"), new SecureRandom());\n"
                    "SecretKeyWithEncapsulation encResult = (SecretKeyWithEncapsulation) kg.generateKey();\n"
                    "byte[] cipherText = encResult.getEncapsulation();\n"
                    "SecretKey aesKey   = encResult;  // 256-bit AES\n\n"
                    "// Decapsulation (receiver)\n"
                    "KeyGenerator kg2 = KeyGenerator.getInstance(\"Kyber\", \"BCPQC\");\n"
                    "kg2.init(new KEMExtractSpec(kp.getPrivate(), cipherText, \"AES\"));\n"
                    "SecretKey aesKey2 = kg2.generateKey();"
                ),
                "verification": "Assert: Arrays.equals(aesKey.getEncoded(), aesKey2.getEncoded())",
            },
            {
                "id": 3,
                "title": "Replace ECDSA with ML-DSA-65 (Dilithium3)",
                "description": "Use Dilithium3 for digital signatures in JWT, code signing, and message signing.",
                "snippet": (
                    "import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;\n\n"
                    "KeyPairGenerator kpg = KeyPairGenerator.getInstance(\"Dilithium\", \"BCPQC\");\n"
                    "kpg.initialize(DilithiumParameterSpec.dilithium3, new SecureRandom());\n"
                    "KeyPair kp = kpg.generateKeyPair();\n\n"
                    "// Sign\n"
                    "Signature signer = Signature.getInstance(\"Dilithium\", \"BCPQC\");\n"
                    "signer.initSign(kp.getPrivate());\n"
                    "signer.update(data);\n"
                    "byte[] signature = signer.sign();\n\n"
                    "// Verify\n"
                    "Signature verifier = Signature.getInstance(\"Dilithium\", \"BCPQC\");\n"
                    "verifier.initVerify(kp.getPublic());\n"
                    "verifier.update(data);\n"
                    "boolean valid = verifier.verify(signature);"
                ),
                "verification": "assertTrue(verifier.verify(signature))",
            },
            {
                "id": 4,
                "title": "Update TLS configuration (JSSE)",
                "description": "Configure Java SSLContext to prefer TLS 1.3 and disable weak cipher suites.",
                "snippet": (
                    "SSLContext ctx = SSLContext.getInstance(\"TLSv1.3\");\n"
                    "ctx.init(keyManagers, trustManagers, new SecureRandom());\n\n"
                    "SSLParameters params = new SSLParameters();\n"
                    "params.setProtocols(new String[]{\"TLSv1.3\"});\n"
                    "// Prefer AES-256-GCM; disable RSA key exchange\n"
                    "params.setCipherSuites(new String[]{\n"
                    "  \"TLS_AES_256_GCM_SHA384\",\n"
                    "  \"TLS_CHACHA20_POLY1305_SHA256\"\n"
                    "});"
                ),
                "verification": "Run SSLLabs scan or: echo | openssl s_client -connect host:443 2>&1 | grep Protocol",
            },
        ],
    },
    "nodejs": {
        "id": "nodejs",
        "name": "Node.js / npm PQC Migration",
        "description": "Migrate Node.js applications from RSA/ECDSA crypto to ML-KEM and ML-DSA using liboqs-node or @noble/post-quantum.",
        "stack": "nodejs",
        "difficulty": "easy",
        "estimated_time": "2–4 hours",
        "prerequisites": [
            "Node.js >= 18 (LTS)",
            "npm or yarn",
            "liboqs-node >= 0.9 OR @noble/post-quantum >= 0.2",
        ],
        "steps": [
            {
                "id": 1,
                "title": "Install PQC library",
                "description": "Choose liboqs-node (native bindings) or @noble/post-quantum (pure JS, no native build).",
                "snippet": (
                    "# Option A: liboqs-node (native, fastest)\n"
                    "npm install liboqs-node\n\n"
                    "# Option B: @noble/post-quantum (pure JS, no liboqs needed)\n"
                    "npm install @noble/post-quantum\n\n"
                    "# Verify\n"
                    "node -e \"require('liboqs-node'); console.log('liboqs OK')\"\n"
                    "# or\n"
                    "node -e \"require('@noble/post-quantum'); console.log('noble/pq OK')\""
                ),
                "verification": "node -e \"require('liboqs-node')\"  # no error = OK",
            },
            {
                "id": 2,
                "title": "Replace RSA encryption with ML-KEM-768",
                "description": "Use ML-KEM for key exchange instead of RSA-OAEP or ECDH.",
                "snippet": (
                    "// @noble/post-quantum\n"
                    "import { ml_kem768 } from '@noble/post-quantum/ml-kem';\n\n"
                    "// Recipient generates key pair\n"
                    "const { publicKey, secretKey } = ml_kem768.keygen();\n\n"
                    "// Sender encapsulates\n"
                    "const { cipherText, sharedSecret: ss1 } = ml_kem768.encapsulate(publicKey);\n\n"
                    "// Recipient decapsulates\n"
                    "const ss2 = ml_kem768.decapsulate(cipherText, secretKey);\n\n"
                    "// ss1 and ss2 are identical — use as AES-256 key\n"
                    "console.assert(Buffer.from(ss1).equals(Buffer.from(ss2)));"
                ),
                "verification": "node test-kem.mjs  # should print no assertion errors",
            },
            {
                "id": 3,
                "title": "Replace ECDSA JWT signing with ML-DSA-65",
                "description": "Sign JWTs or payloads with ML-DSA instead of ES256/RS256.",
                "snippet": (
                    "// @noble/post-quantum\n"
                    "import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';\n\n"
                    "const { publicKey, secretKey } = ml_dsa65.keygen();\n\n"
                    "const msg = new TextEncoder().encode('payload to sign');\n"
                    "const sig = ml_dsa65.sign(secretKey, msg);\n\n"
                    "const valid = ml_dsa65.verify(publicKey, msg, sig);\n"
                    "console.log('Signature valid:', valid);  // true"
                ),
                "verification": "node test-dsa.mjs  # should print: Signature valid: true",
            },
            {
                "id": 4,
                "title": "Update TLS server (https module)",
                "description": "Configure Node.js HTTPS server to prefer TLS 1.3 and disable weak ciphers.",
                "snippet": (
                    "const https = require('https');\n"
                    "const server = https.createServer({\n"
                    "  key:  fs.readFileSync('server.key'),\n"
                    "  cert: fs.readFileSync('server.crt'),\n"
                    "  minVersion:   'TLSv1.3',\n"
                    "  ciphers:      'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',\n"
                    "  honorCipherOrder: false,\n"
                    "}, app);"
                ),
                "verification": "curl -v --tlsv1.3 https://localhost:3000/ 2>&1 | grep 'TLSv1.3'",
            },
        ],
    },
    "python": {
        "id": "python",
        "name": "Python PQC Migration",
        "description": "Migrate Python applications using cryptography, PyCryptodome, or paramiko to PQC-safe algorithms.",
        "stack": "python",
        "difficulty": "easy",
        "estimated_time": "2–3 hours",
        "prerequisites": [
            "Python >= 3.10",
            "pip",
            "oqs-python >= 0.9 or cryptography >= 44 with liboqs",
        ],
        "steps": [
            {
                "id": 1,
                "title": "Install oqs-python",
                "description": "liboqs Python bindings — wraps the C liboqs library for ML-KEM and ML-DSA.",
                "snippet": (
                    "# Install liboqs system library first\n"
                    "# Ubuntu: sudo apt-get install -y liboqs-dev\n"
                    "# macOS:  brew install liboqs\n\n"
                    "pip install oqs\n\n"
                    "# Verify\n"
                    "python -c \"import oqs; print(oqs.get_enabled_KEM_mechanisms()[:3])\""
                ),
                "verification": "python -c \"import oqs; print('OK')\"",
            },
            {
                "id": 2,
                "title": "Replace RSA/ECDH with ML-KEM-768",
                "description": "Use oqs.KeyEncapsulation for key exchange in place of RSA PKCS#1 or ECDH.",
                "snippet": (
                    "import oqs\n\n"
                    "# Recipient\n"
                    "kem = oqs.KeyEncapsulation('Kyber768')  # ML-KEM-768\n"
                    "pub_key = kem.generate_keypair()\n\n"
                    "# Sender\n"
                    "kem_enc = oqs.KeyEncapsulation('Kyber768')\n"
                    "ciphertext, shared_secret_enc = kem_enc.encap_secret(pub_key)\n\n"
                    "# Recipient decapsulates\n"
                    "shared_secret_dec = kem.decap_secret(ciphertext)\n\n"
                    "assert shared_secret_enc == shared_secret_dec\n"
                    "# Use shared_secret as AES-256 key"
                ),
                "verification": "python test_kem.py  # no AssertionError",
            },
            {
                "id": 3,
                "title": "Replace ECDSA with ML-DSA-65",
                "description": "Use oqs.Signature('Dilithium3') for signing in place of ECDSA or RSA-PSS.",
                "snippet": (
                    "import oqs\n\n"
                    "sig = oqs.Signature('Dilithium3')  # ML-DSA-65\n"
                    "pub_key = sig.generate_keypair()\n\n"
                    "message = b'data to sign'\n"
                    "signature = sig.sign(message)\n\n"
                    "verifier = oqs.Signature('Dilithium3')\n"
                    "is_valid = verifier.verify(message, signature, pub_key)\n"
                    "assert is_valid, 'Signature verification failed'\n"
                    "print('Signature valid:', is_valid)"
                ),
                "verification": "python test_dsa.py  # prints: Signature valid: True",
            },
            {
                "id": 4,
                "title": "Update SSH keys (paramiko / OpenSSH)",
                "description": "Generate ML-DSA SSH host keys and update known_hosts for post-quantum SSH.",
                "snippet": (
                    "# Generate PQC SSH key (requires OpenSSH >= 9.0 with OQS patch)\n"
                    "ssh-keygen -t dilithium3 -f ~/.ssh/id_dilithium3 -C 'pqc-key'\n\n"
                    "# Or generate in Python via paramiko + oqs\n"
                    "import oqs, paramiko\n"
                    "sig = oqs.Signature('Dilithium3')\n"
                    "pub = sig.generate_keypair()\n"
                    "# Wrap in OpenSSH wire format for host key"
                ),
                "verification": "ssh-keyscan -t dilithium3 localhost",
            },
        ],
    },
    "golang": {
        "id": "golang",
        "name": "Go / Golang PQC Migration",
        "description": "Migrate Go applications to ML-KEM and ML-DSA using the cloudflare/circl or open-quantum-safe/liboqs-go libraries.",
        "stack": "golang",
        "difficulty": "medium",
        "estimated_time": "3–5 hours",
        "prerequisites": [
            "Go >= 1.21",
            "github.com/cloudflare/circl >= 1.3.7  OR  github.com/open-quantum-safe/liboqs-go",
            "CGO enabled (for liboqs-go) or pure-Go (circl)",
        ],
        "steps": [
            {
                "id": 1,
                "title": "Add circl or liboqs-go dependency",
                "description": "cloudflare/circl is pure Go (no CGO); liboqs-go wraps C liboqs for broader algorithm support.",
                "snippet": (
                    "# Pure Go (recommended for most projects)\n"
                    "go get github.com/cloudflare/circl@latest\n\n"
                    "# Or liboqs-go (CGO, full algorithm suite)\n"
                    "go get github.com/open-quantum-safe/liboqs-go/oqs@latest\n\n"
                    "# Verify\n"
                    "go list -m github.com/cloudflare/circl"
                ),
                "verification": "go build ./...  # no import errors",
            },
            {
                "id": 2,
                "title": "Replace ECDH with ML-KEM-768 (circl)",
                "description": "Use circl's kem/kyber package for key encapsulation.",
                "snippet": (
                    "import (\n"
                    "    \"github.com/cloudflare/circl/kem/kyber/kyber768\"\n"
                    ")\n\n"
                    "scheme := kyber768.Scheme()\n\n"
                    "// Recipient generates key pair\n"
                    "pub, priv, _ := scheme.GenerateKeyPair()\n\n"
                    "// Sender encapsulates\n"
                    "ct, ss1, _ := scheme.Encapsulate(pub)\n\n"
                    "// Recipient decapsulates\n"
                    "ss2, _ := scheme.Decapsulate(priv, ct)\n\n"
                    "// ss1 == ss2 — use as AES-256-GCM key\n"
                    "fmt.Println(bytes.Equal(ss1, ss2)) // true"
                ),
                "verification": "go test ./kem/... -run TestMLKEM",
            },
            {
                "id": 3,
                "title": "Replace ECDSA with ML-DSA-65 (circl)",
                "description": "Use circl's sign/dilithium package for digital signatures.",
                "snippet": (
                    "import (\n"
                    "    dilithium \"github.com/cloudflare/circl/sign/dilithium/mode3\"\n"
                    ")\n\n"
                    "// Key generation\n"
                    "pub, priv, _ := dilithium.GenerateKey(rand.Reader)\n\n"
                    "// Sign\n"
                    "msg := []byte(\"message to sign\")\n"
                    "sig := make([]byte, dilithium.SignatureSize)\n"
                    "dilithium.SignTo(priv, msg, nil, false, sig)\n\n"
                    "// Verify\n"
                    "valid := dilithium.Verify(pub, msg, nil, sig)\n"
                    "fmt.Println(\"Valid:\", valid) // true"
                ),
                "verification": "go test ./sign/... -run TestMLDSA",
            },
            {
                "id": 4,
                "title": "Configure TLS 1.3 with hybrid PQC",
                "description": "Use Go's crypto/tls with TLS 1.3 preference. For X25519Kyber768, use cloudflare's ztls fork or an nginx proxy.",
                "snippet": (
                    "cfg := &tls.Config{\n"
                    "    MinVersion: tls.VersionTLS13,\n"
                    "    CipherSuites: []uint16{\n"
                    "        tls.TLS_AES_256_GCM_SHA384,\n"
                    "        tls.TLS_CHACHA20_POLY1305_SHA256,\n"
                    "    },\n"
                    "    CurvePreferences: []tls.CurveID{\n"
                    "        tls.X25519,  // until Go stdlib adds Kyber\n"
                    "        tls.CurveP256,\n"
                    "    },\n"
                    "}\n"
                    "// For X25519Kyber768 today: use nginx reverse proxy\n"
                    "// or cloudflare/go fork: tls.X25519Kyber768Draft00"
                ),
                "verification": "go test -run TestTLS ./...",
            },
        ],
    },
}


# ── DB helpers ─────────────────────────────────────────────────────────────────

def _init_tables() -> None:
    with feature_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS playbook_progress (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id      TEXT    NOT NULL,
                asset_id    TEXT    NOT NULL,
                playbook_id TEXT    NOT NULL,
                step_id     INTEGER NOT NULL,
                status      TEXT    NOT NULL DEFAULT 'pending',
                notes       TEXT,
                updated_at  TEXT    NOT NULL,
                UNIQUE(org_id, asset_id, playbook_id, step_id)
            )
        """)
        conn.commit()


# ── Public API ─────────────────────────────────────────────────────────────────

def list_playbooks() -> List[Dict[str, Any]]:
    """Return summary list of all available playbooks (no step details)."""
    return [
        {
            "id":             pb["id"],
            "name":           pb["name"],
            "description":    pb["description"],
            "stack":          pb["stack"],
            "difficulty":     pb["difficulty"],
            "estimated_time": pb["estimated_time"],
            "step_count":     len(pb["steps"]),
            "prerequisites":  pb["prerequisites"],
        }
        for pb in _PLAYBOOKS.values()
    ]


def get_playbook(playbook_id: str) -> Optional[Dict[str, Any]]:
    """Return full playbook including steps, or None if not found."""
    return _PLAYBOOKS.get(playbook_id)


def get_progress(org_id: str, asset_id: str, playbook_id: str) -> Dict[str, Any]:
    """Return per-step completion status for an asset+playbook pair."""
    _init_tables()
    pb = _PLAYBOOKS.get(playbook_id)
    if not pb:
        return {"ok": False, "error": "Unknown playbook"}

    with feature_conn() as conn:
        rows = conn.execute(
            "SELECT step_id, status, notes, updated_at FROM playbook_progress "
            "WHERE org_id=? AND asset_id=? AND playbook_id=?",
            (org_id, asset_id, playbook_id),
        ).fetchall()

    progress_map = {r["step_id"]: dict(r) for r in rows}
    steps_out = []
    completed = 0
    for step in pb["steps"]:
        s_id = step["id"]
        prog = progress_map.get(s_id, {})
        status = prog.get("status", "pending")
        if status == "completed":
            completed += 1
        steps_out.append({
            "id":          s_id,
            "title":       step["title"],
            "description": step["description"],
            "snippet":     step["snippet"],
            "verification":step["verification"],
            "status":      status,
            "notes":       prog.get("notes", ""),
            "updated_at":  prog.get("updated_at", ""),
        })

    total = len(pb["steps"])
    return {
        "ok":            True,
        "org_id":        org_id,
        "asset_id":      asset_id,
        "playbook_id":   playbook_id,
        "playbook_name": pb["name"],
        "steps":         steps_out,
        "completed":     completed,
        "total":         total,
        "pct_complete":  round(completed / total * 100) if total else 0,
    }


def update_step(
    org_id: str,
    asset_id: str,
    playbook_id: str,
    step_id: int,
    status: str,
    notes: str = "",
) -> Dict[str, Any]:
    """Mark a playbook step as pending / in_progress / completed."""
    if status not in ("pending", "in_progress", "completed", "skipped"):
        return {"ok": False, "error": "Invalid status"}
    pb = _PLAYBOOKS.get(playbook_id)
    if not pb:
        return {"ok": False, "error": "Unknown playbook"}
    step_ids = {s["id"] for s in pb["steps"]}
    if step_id not in step_ids:
        return {"ok": False, "error": "Invalid step_id"}

    _init_tables()
    now = datetime.now(timezone.utc).isoformat()
    with feature_conn() as conn:
        conn.execute(
            """
            INSERT INTO playbook_progress (org_id, asset_id, playbook_id, step_id, status, notes, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(org_id, asset_id, playbook_id, step_id)
            DO UPDATE SET status=excluded.status, notes=excluded.notes, updated_at=excluded.updated_at
            """,
            (org_id, asset_id, playbook_id, step_id, status, notes, now),
        )
        conn.commit()

    return {"ok": True, "step_id": step_id, "status": status, "updated_at": now}


def list_asset_progress(org_id: str) -> List[Dict[str, Any]]:
    """Return aggregated progress across all asset+playbook pairs for an org."""
    _init_tables()
    with feature_conn() as conn:
        rows = conn.execute(
            """
            SELECT asset_id, playbook_id,
                   COUNT(*) as total_steps,
                   SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END) as done,
                   MAX(updated_at) as last_update
            FROM playbook_progress
            WHERE org_id=?
            GROUP BY asset_id, playbook_id
            ORDER BY last_update DESC
            """,
            (org_id,),
        ).fetchall()

    out = []
    for r in rows:
        pb = _PLAYBOOKS.get(r["playbook_id"], {})
        total = len(pb.get("steps", [])) or r["total_steps"]
        out.append({
            "asset_id":     r["asset_id"],
            "playbook_id":  r["playbook_id"],
            "playbook_name":pb.get("name", r["playbook_id"]),
            "completed":    r["done"],
            "total":        total,
            "pct_complete": round(r["done"] / total * 100) if total else 0,
            "last_update":  r["last_update"],
        })
    return out


def recommend_playbook(stack_hint: str) -> Optional[Dict[str, Any]]:
    """
    Given a technology hint (e.g. from a scan result), return the best matching playbook summary.
    """
    hint = stack_hint.lower()
    mapping = {
        "nginx":    "nginx",
        "openssl":  "openssl",
        "java":     "java",
        "spring":   "java",
        "kotlin":   "java",
        "node":     "nodejs",
        "express":  "nodejs",
        "next":     "nodejs",
        "python":   "python",
        "django":   "python",
        "flask":    "python",
        "fastapi":  "python",
        "go":       "golang",
        "golang":   "golang",
        "gin":      "golang",
        "echo":     "golang",
    }
    for key, pb_id in mapping.items():
        if key in hint:
            pb = _PLAYBOOKS.get(pb_id)
            if pb:
                return {
                    "id":             pb["id"],
                    "name":           pb["name"],
                    "stack":          pb["stack"],
                    "difficulty":     pb["difficulty"],
                    "estimated_time": pb["estimated_time"],
                    "step_count":     len(pb["steps"]),
                }
    return None
