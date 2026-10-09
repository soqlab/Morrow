"""PQC Knowledge Base — searchable library of migration guides, algorithm docs, CVE mappings."""
from typing import Optional

ARTICLES = [
    {
        "slug": "ml-kem-overview",
        "title": "ML-KEM (CRYSTALS-Kyber) Overview",
        "category": "Algorithms",
        "tags": ["ml-kem", "kyber", "kem", "nist", "fips-203"],
        "summary": "ML-KEM (FIPS 203) is NIST's standardized key-encapsulation mechanism based on Module-LWE. Replaces RSA and ECDH for key exchange.",
        "body": """## What is ML-KEM?
ML-KEM (Module Lattice-based Key Encapsulation Mechanism) was standardized as FIPS 203 in August 2024. It is based on the CRYSTALS-Kyber submission and provides quantum-resistant key exchange.

## Parameter Sets
| Set | Security | Public Key | Ciphertext | Shared Secret |
|-----|----------|-----------|-----------|---------------|
| ML-KEM-512  | Level 1 (AES-128) | 800 B  | 768 B  | 32 B |
| ML-KEM-768  | Level 3 (AES-192) | 1184 B | 1088 B | 32 B |
| ML-KEM-1024 | Level 5 (AES-256) | 1568 B | 1568 B | 32 B |

## Migration Path
1. Replace RSA/ECDH key exchange with ML-KEM-768 (minimum) or ML-KEM-1024 (federal)
2. Use hybrid mode: X25519 + ML-KEM-768 during transition
3. OpenSSL 3.5+ supports ML-KEM natively; enable with `groups = X25519MLKEM768`

## CVE Notes
No CVEs against the NIST-standardized algorithm. Side-channel risks in naive implementations — use vetted libraries (liboqs, BouncyCastle PQC, ML-KEM reference).
""",
        "severity_relevance": "CRITICAL",
        "updated_at": "2025-08-01",
    },
    {
        "slug": "ml-dsa-overview",
        "title": "ML-DSA (CRYSTALS-Dilithium) Overview",
        "category": "Algorithms",
        "tags": ["ml-dsa", "dilithium", "signature", "nist", "fips-204"],
        "summary": "ML-DSA (FIPS 204) is NIST's standardized digital signature algorithm. Replaces RSA-PSS and ECDSA for code signing and authentication.",
        "body": """## What is ML-DSA?
ML-DSA (Module Lattice-based Digital Signature Algorithm) was standardized as FIPS 204 in August 2024. It is based on CRYSTALS-Dilithium and provides quantum-resistant digital signatures.

## Parameter Sets
| Set | Security | Public Key | Signature | Private Key |
|-----|----------|-----------|-----------|-------------|
| ML-DSA-44 | Level 2 | 1312 B | 2420 B | 2528 B |
| ML-DSA-65 | Level 3 | 1952 B | 3293 B | 4000 B |
| ML-DSA-87 | Level 5 | 2592 B | 4595 B | 4864 B |

## Migration Path
1. Replace ECDSA/RSA signatures with ML-DSA-65 (recommended baseline)
2. Use hybrid certificates: classical + ML-DSA during transition (IETF draft-composite-sigs)
3. GitHub Actions: sign artifacts with ML-DSA-65 using sigstore-python PQC branch

## Key Note
ML-DSA is deterministic — no per-signature randomness required, eliminating a class of nonce-reuse vulnerabilities present in ECDSA.
""",
        "severity_relevance": "CRITICAL",
        "updated_at": "2025-08-01",
    },
    {
        "slug": "slh-dsa-overview",
        "title": "SLH-DSA (SPHINCS+) Overview",
        "category": "Algorithms",
        "tags": ["slh-dsa", "sphincs", "hash-based", "signature", "fips-205"],
        "summary": "SLH-DSA (FIPS 205) is a stateless hash-based signature scheme. Highly conservative security assumptions — ideal for root CAs and firmware signing.",
        "body": """## What is SLH-DSA?
SLH-DSA (Stateless Hash-based Digital Signature Algorithm) standardized as FIPS 205. Unlike ML-DSA, its security reduces only to the collision resistance of the underlying hash function.

## When to Use SLH-DSA vs ML-DSA
- **SLH-DSA**: Root CAs, firmware signing, long-lived certificates (30+ year horizon). Larger signatures (~8-50 KB) but maximum security conservatism.
- **ML-DSA**: Everything else — TLS, code signing, JWTs. Smaller signatures (2-5 KB), faster.

## Variants
- `slh-dsa-sha2-128s` / `slh-dsa-sha2-128f` — small vs fast, NIST Level 1
- `slh-dsa-sha2-256s` / `slh-dsa-sha2-256f` — small vs fast, NIST Level 5

## Implementation
Available in BouncyCastle ≥1.78, liboqs ≥0.10, Rustls PQC branch.
""",
        "severity_relevance": "HIGH",
        "updated_at": "2025-08-01",
    },
    {
        "slug": "hybrid-tls-migration",
        "title": "Hybrid TLS Migration Guide",
        "category": "Migration",
        "tags": ["tls", "hybrid", "x25519", "ml-kem", "nginx", "openssl"],
        "summary": "Step-by-step guide to enabling hybrid PQC TLS (X25519+ML-KEM-768) in nginx, Apache, and Go services. Backward-compatible — works with classical clients.",
        "body": """## What is Hybrid TLS?
Hybrid TLS combines a classical key exchange (X25519) with a PQC key exchange (ML-KEM) in the same TLS handshake. The session key is derived from both — secure if either is unbroken.

## nginx (OpenSSL 3.5+)
```nginx
ssl_protocols TLSv1.3;
ssl_ecdh_curve X25519MLKEM768:X25519;
```

## Go (1.23+)
```go
tlsConfig := &tls.Config{
    CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
}
```

## Python (openssl 3.5 + pyopenssl)
```python
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.set_ecdh_curve("X25519MLKEM768")
```

## Compatibility
- Chrome 131+ supports X25519MLKEM768 by default
- Firefox 132+ supports it behind a flag
- Classical-only clients fall back to X25519 automatically
- No certificate changes needed — hybrid is key exchange only

## Test
```bash
openssl s_client -connect example.com:443 -groups X25519MLKEM768
# Look for: Server Temp Key: X25519MLKEM768
```
""",
        "severity_relevance": "HIGH",
        "updated_at": "2025-09-01",
    },
    {
        "slug": "hndl-threat-model",
        "title": "Harvest Now Decrypt Later (HNDL) Threat Model",
        "category": "Threats",
        "tags": ["hndl", "threat", "harvest", "nation-state", "q-day"],
        "summary": "HNDL attacks capture ciphertext today for decryption after Q-Day. Any data with a confidentiality horizon beyond 2030 is at risk NOW.",
        "body": """## What is HNDL?
Harvest Now, Decrypt Later (HNDL) is a threat where adversaries collect encrypted data today, store it, and decrypt it once a Cryptographically Relevant Quantum Computer (CRQC) is available.

## Timeline Risk Assessment
| Data Type | Confidentiality Horizon | HNDL Risk |
|-----------|------------------------|-----------|
| Session tokens | Hours | LOW |
| Financial records | 7 years | HIGH |
| Health records | 50 years | CRITICAL |
| Government secrets | 25+ years | CRITICAL |
| IP / trade secrets | Variable | HIGH-CRITICAL |

## Known HNDL Campaigns
- 2022: US Treasury breach — exfiltrated TLS sessions (attributed)
- 2023: Multiple SCADA vendors — encrypted OT traffic captured
- 2024: Healthcare sector — patient record tunnels harvested

## Defense
1. Migrate key exchange to ML-KEM NOW — even before Q-Day, HNDL stops at key exchange
2. Enable Perfect Forward Secrecy (already in TLS 1.3) to limit blast radius
3. Rotate long-lived keys aggressively — minimize harvested-ciphertext window
4. Use HNDL canary tokens to detect adversarial presence in your network
""",
        "severity_relevance": "CRITICAL",
        "updated_at": "2025-07-01",
    },
    {
        "slug": "openssl-pqc-migration",
        "title": "OpenSSL 3.x PQC Migration",
        "category": "Libraries",
        "tags": ["openssl", "oqs", "liboqs", "python", "c", "library"],
        "summary": "How to enable PQC in OpenSSL 3.x via the OQS provider. Covers installation, configuration, and testing for Linux, macOS, and Docker.",
        "body": """## OpenSSL + OQS Provider
The OQS (Open Quantum Safe) provider for OpenSSL adds ML-KEM, ML-DSA, SLH-DSA, and hybrid algorithms to OpenSSL 3.x.

## Install
```bash
# Ubuntu/Debian
sudo apt-get install liboqs-dev
# Build oqs-provider from source (recommended for prod)
git clone https://github.com/open-quantum-safe/oqs-provider
cd oqs-provider && cmake -DOQS_PROVIDER_BUILD_STATIC=ON . && make && sudo make install
```

## Configure
```ini
# /etc/ssl/openssl.cnf
[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect

[oqsprovider_sect]
activate = 1
module = /usr/lib/ossl-modules/oqsprovider.so
```

## Test
```bash
openssl list -kem-algorithms | grep ML-KEM
openssl genpkey -algorithm ML-DSA-65 -out private.pem
openssl pkey -in private.pem -pubout -out public.pem
```

## Docker
```dockerfile
FROM openquantumsafe/curl:latest
# Includes oqs-provider pre-configured
```
""",
        "severity_relevance": "HIGH",
        "updated_at": "2025-09-01",
    },
    {
        "slug": "java-bouncycastle-pqc",
        "title": "Java / BouncyCastle PQC Migration",
        "category": "Libraries",
        "tags": ["java", "bouncycastle", "bc-pqc", "spring", "jvm"],
        "summary": "Migrating Java applications from classical JCE (RSA/ECDSA) to PQC using BouncyCastle BCPQC jar. Includes Spring Boot examples.",
        "body": """## Dependencies
```xml
<dependency>
  <groupId>org.bouncycastle</groupId>
  <artifactId>bcprov-jdk18on</artifactId>
  <version>1.79</version>
</dependency>
<dependency>
  <groupId>org.bouncycastle</groupId>
  <artifactId>bcpqc-jdk18on</artifactId>
  <version>1.79</version>
</dependency>
```

## ML-KEM Key Exchange
```java
Security.addProvider(new BouncyCastlePostQuantumProvider());
KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", "BCPQC");
kpg.initialize(MLKEMParameterSpec.ml_kem_768);
KeyPair kp = kpg.generateKeyPair();
```

## ML-DSA Signing
```java
KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", "BCPQC");
kpg.initialize(MLDSAParameterSpec.ml_dsa_65);
KeyPair kp = kpg.generateKeyPair();
Signature sig = Signature.getInstance("ML-DSA", "BCPQC");
sig.initSign(kp.getPrivate());
sig.update(data);
byte[] signature = sig.sign();
```

## Known Issue: CVE-2024-29857
BouncyCastle <1.78 has an infinite loop in LDAP DN parsing. Unrelated to PQC but update before deploying.
""",
        "severity_relevance": "MEDIUM",
        "updated_at": "2025-08-01",
    },
    {
        "slug": "cnsa-2-0-timeline",
        "title": "CNSA 2.0 Compliance Timeline",
        "category": "Compliance",
        "tags": ["cnsa", "nsa", "timeline", "dod", "federal", "deadline"],
        "summary": "NSA's Commercial National Security Algorithm Suite 2.0 mandates PQC adoption for national security systems by 2030. Federal contractors must comply earlier.",
        "body": """## CNSA 2.0 Deadlines
| Date | Requirement |
|------|-------------|
| 2025 | Software and firmware signing: ML-DSA or SLH-DSA required |
| 2026 | Network equipment and browsers: ML-KEM required |
| 2027 | Operating systems: full PQC support mandatory |
| 2030 | All NSS systems: complete PQC migration, classical algorithms deprecated |

## Scope
CNSA 2.0 applies to all National Security Systems (NSS) and their supply chain. Contractors providing software, services, or infrastructure to DoD, IC, or NSS owners are directly affected.

## Algorithms Required
- Key exchange: ML-KEM-1024 (NSS minimum) or ML-KEM-768 (commercial)
- Digital signatures: ML-DSA-87 (NSS) or ML-DSA-65 (commercial)
- Alternative signature: SLH-DSA-SHA2-256s for long-lived certificates
- Hash: SHA-384 minimum

## Prohibited (post-deadline)
RSA, ECDSA, ECDH, DH, DSA — all classical asymmetric algorithms.

## Affected Systems
VPNs, PKI, code signing, TLS, SSH, encrypted storage, firmware update mechanisms.
""",
        "severity_relevance": "CRITICAL",
        "updated_at": "2025-07-01",
    },
    {
        "slug": "pqc-ssh-migration",
        "title": "PQC SSH Migration (OpenSSH 9.x)",
        "category": "Migration",
        "tags": ["ssh", "openssh", "sftp", "server", "kex"],
        "summary": "OpenSSH 9.0+ ships with ML-KEM-768 hybrid key exchange by default. How to enable, verify, and configure for PQC-only environments.",
        "body": """## OpenSSH 9.0+
OpenSSH 9.0 (2022) enabled `sntrup761x25519-sha512@openssh.com` by default — a hybrid post-quantum key exchange combining Streamlined NTRU Prime with X25519.

OpenSSH 9.9 (2025) adds ML-KEM-768 hybrid as preferred: `mlkem768x25519-sha256`.

## Check Your Version
```bash
ssh -V
# OpenSSH_9.9p1 or later recommended
```

## Server Configuration
```bash
# /etc/ssh/sshd_config
KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256
HostKeyAlgorithms ssh-ed25519,ecdsa-sha2-nistp256
```

## Client Configuration
```bash
# ~/.ssh/config
KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com
```

## Verify PQC KEX in Use
```bash
ssh -vvv user@host 2>&1 | grep "kex:"
# Expected: kex: algorithm: mlkem768x25519-sha256
```

## Host Keys
Host keys (RSA/ECDSA) are for authentication, not encryption — less urgent for HNDL. However, NIST recommends moving to Ed25519 now and ML-DSA when OpenSSH support lands.
""",
        "severity_relevance": "HIGH",
        "updated_at": "2025-09-01",
    },
    {
        "slug": "pqc-certificates-hybrid",
        "title": "Hybrid PQC Certificates (X.509)",
        "category": "Migration",
        "tags": ["certificate", "x509", "pki", "hybrid", "tls", "ca"],
        "summary": "Hybrid X.509 certificates carry both a classical (RSA/ECDSA) and PQC (ML-DSA) signature. Backward-compatible with classical clients, quantum-resistant for PQC clients.",
        "body": """## Why Hybrid Certificates?
During the transition period, clients need to verify certificates using either classical or PQC algorithms depending on their capabilities. Hybrid certs embed both, signed by the CA with both algorithms.

## Approaches
1. **Composite signatures** (IETF draft-ounsworth-pq-composite-sigs): Single certificate with composite key and signature field
2. **Dual-key certificates** (draft-lamps-pq-composite-kem): Two certificates bound together
3. **SubjectAltPublicKeyInfo** (draft-lamps-cert-binding-for-multi-auth): Classical cert with PQC key in extension

## Recommended: Composite (draft-ounsworth)
```bash
# Generate composite ML-DSA-65 + ECDSA P-256 cert
openssl genpkey -algorithm id-MLDSA65-ECDSA-P256-SHA512 \
  -provider oqsprovider -out composite.key
openssl req -new -key composite.key -out composite.csr
openssl x509 -req -in composite.csr -signkey composite.key -out composite.crt
```

## Current CA Support
- DigiCert: Hybrid pilot program (2025)
- Let's Encrypt: Not yet (planned 2026)
- Private CA via EJBCA 8.x or Vault PKI with oqs-provider: Available now

## Timeline
Issue hybrid certs now for any certificate with >2 year lifetime to avoid reissuance before CRQC arrival.
""",
        "severity_relevance": "HIGH",
        "updated_at": "2025-08-01",
    },
]


def search(query: str, category: Optional[str] = None, limit: int = 20) -> list[dict]:
    q = query.lower().strip()
    results = []
    for article in ARTICLES:
        if category and article["category"].lower() != category.lower():
            continue
        score = 0
        if q in article["title"].lower():
            score += 10
        if q in article["summary"].lower():
            score += 5
        if any(q in t for t in article["tags"]):
            score += 8
        if q in article["body"].lower():
            score += 2
        # multi-word partial
        for word in q.split():
            if word in article["title"].lower() or any(word in t for t in article["tags"]):
                score += 3
        if score > 0 or not q:
            results.append({**article, "_score": score})

    results.sort(key=lambda x: x["_score"], reverse=True)
    return [_strip_body(r) for r in results[:limit]]


def get_article(slug: str) -> Optional[dict]:
    for a in ARTICLES:
        if a["slug"] == slug:
            return a
    return None


def list_categories() -> list[str]:
    return sorted(set(a["category"] for a in ARTICLES))


def list_all(category: Optional[str] = None) -> list[dict]:
    items = ARTICLES if not category else [a for a in ARTICLES if a["category"] == category]
    return [_strip_body(a) for a in items]


def _strip_body(article: dict) -> dict:
    return {k: v for k, v in article.items() if k not in ("body", "_score")}
