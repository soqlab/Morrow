/* Morrow instrument: reference data. Every number comes from the cited standard; keep it that way.
   Sizes are in bytes. Where a value depends on parameters not listed, the field is omitted rather
   than guessed. Ported from the SOQLAB reference (19 algorithms) and extended with a dated history
   of the internet's cryptography, each event with its primary source. */
(function () {
  "use strict";
  var NIST = {
    fips203: { label: "NIST FIPS 203: ML-KEM (Aug 2024)", href: "https://csrc.nist.gov/pubs/fips/203/final" },
    fips204: { label: "NIST FIPS 204: ML-DSA (Aug 2024)", href: "https://csrc.nist.gov/pubs/fips/204/final" },
    fips205: { label: "NIST FIPS 205: SLH-DSA (Aug 2024)", href: "https://csrc.nist.gov/pubs/fips/205/final" },
    fips1865: { label: "NIST FIPS 186-5: Digital Signature Standard (Feb 2023)", href: "https://csrc.nist.gov/pubs/fips/186-5/final" },
    fips197: { label: "NIST FIPS 197: Advanced Encryption Standard", href: "https://csrc.nist.gov/pubs/fips/197/upd1/final" },
    fips1804: { label: "NIST FIPS 180-4: Secure Hash Standard", href: "https://csrc.nist.gov/pubs/fips/180-4/upd1/final" },
    sp800208: { label: "NIST SP 800-208: Stateful Hash-Based Signature Schemes (Oct 2020)", href: "https://csrc.nist.gov/pubs/sp/800/208/final" },
    sp800186: { label: "NIST SP 800-186: Elliptic Curve Domain Parameters", href: "https://csrc.nist.gov/pubs/sp/800/186/final" },
    sp80056a: { label: "NIST SP 800-56A Rev. 3: Discrete-log key establishment", href: "https://csrc.nist.gov/pubs/sp/800/56/a/r3/final" },
    sp80056b: { label: "NIST SP 800-56B Rev. 2: Integer-factorization key establishment", href: "https://csrc.nist.gov/pubs/sp/800/56/b/r2/final" },
    sp80057: { label: "NIST SP 800-57 Part 1 Rev. 5: Key Management (security strengths)", href: "https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final" },
    ir8547: { label: "NIST IR 8547 (initial public draft): Transition to Post-Quantum Cryptography Standards", href: "https://csrc.nist.gov/pubs/ir/8547/ipd" },
    ir8545: { label: "NIST IR 8545: Fourth Round of the NIST PQC Process (Mar 2025)", href: "https://csrc.nist.gov/pubs/ir/8545/final" },
    pqc: { label: "NIST Post-Quantum Cryptography project", href: "https://csrc.nist.gov/projects/post-quantum-cryptography" }
  };
  function RFC(n, t) { return { label: "RFC " + n + ": " + t, href: "https://www.rfc-editor.org/rfc/rfc" + n }; }
  var TLS_MLKEM = { label: "IETF draft-ietf-tls-ecdhe-mlkem: hybrid ECDHE-MLKEM for TLS 1.3", href: "https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/" };
  var GIDNEY = { label: "Gidney (2025): How to factor 2048 bit RSA integers with less than a million noisy qubits, arXiv:2505.15917", href: "https://arxiv.org/abs/2505.15917" };
  var SHOR = "Shor's algorithm on a large, error-corrected quantum computer solves the underlying problem (factoring or discrete logarithms) efficiently, so key size does not save it. Traffic recorded today can be decrypted once such a machine exists.";
  var IR8547 = "NIST IR 8547 (draft) proposes deprecating 112-bit-security RSA and elliptic-curve schemes after 2030 and disallowing all of them after 2035.";

  var A = [
    { id: "ml-kem", name: "ML-KEM", aka: ["Kyber", "CRYSTALS-Kyber", "FIPS 203", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "MLKEM"], kind: "Key encapsulation", family: "Post-quantum",
      status: "Standardised. Final since 13 August 2024.", standard: NIST.fips203, risk: "resistant",
      riskText: "Built on the module learning-with-errors problem, for which no efficient quantum algorithm is known. NIST's primary choice for general key establishment.",
      summary: "The lattice-based key-encapsulation mechanism that replaces RSA and elliptic-curve key exchange. Two parties end up with the same 32-byte shared secret.",
      params: { cols: ["Parameter set", "Category", "Encapsulation key", "Decapsulation key", "Ciphertext", "Shared secret"], rows: [["ML-KEM-512", "1", "800", "1,632", "768", "32"], ["ML-KEM-768", "3", "1,184", "2,400", "1,088", "32"], ["ML-KEM-1024", "5", "1,568", "3,168", "1,568", "32"]] },
      seenIn: "TLS 1.3 as part of the hybrid group X25519MLKEM768, which current browsers and CDNs negotiate by default.", related: ["x25519mlkem768", "hqc", "x25519", "rsa-2048"], sources: [NIST.fips203, NIST.ir8547, NIST.pqc] },
    { id: "ml-dsa", name: "ML-DSA", aka: ["Dilithium", "CRYSTALS-Dilithium", "FIPS 204", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "MLDSA"], kind: "Signature", family: "Post-quantum",
      status: "Standardised. Final since 13 August 2024.", standard: NIST.fips204, risk: "resistant",
      riskText: "Lattice-based (module LWE and module SIS). No efficient quantum attack is known. NIST's primary choice for general-purpose signatures.",
      summary: "The lattice-based signature scheme that replaces RSA and ECDSA signatures. Larger keys and signatures than elliptic curves, fast to sign and verify.",
      params: { cols: ["Parameter set", "Category", "Public key", "Private key", "Signature"], rows: [["ML-DSA-44", "2", "1,312", "2,560", "2,420"], ["ML-DSA-65", "3", "1,952", "4,032", "3,309"], ["ML-DSA-87", "5", "2,592", "4,896", "4,627"]] },
      seenIn: "Morrow signs its migration proofs and its page manifest with ML-DSA-65 next to Ed25519 when the server's crypto library provides it.", related: ["slh-dsa", "fn-dsa", "ecdsa-p256", "rsa-2048"], sources: [NIST.fips204, NIST.ir8547, NIST.pqc] },
    { id: "slh-dsa", name: "SLH-DSA", aka: ["SPHINCS+", "SPHINCS", "FIPS 205", "SLH-DSA-SHA2-128s", "SLH-DSA-SHAKE-128s"], kind: "Signature", family: "Post-quantum",
      status: "Standardised. Final since 13 August 2024.", standard: NIST.fips205, risk: "resistant",
      riskText: "Its security rests only on the hash function. A conservative backup to ML-DSA that does not depend on lattice assumptions.",
      summary: "A stateless hash-based signature scheme. Tiny keys, large and slow signatures. 12 parameter sets: SHA-2 or SHAKE, small (s) or fast (f), at three security levels.",
      params: { cols: ["Parameter set (SHA-2 or SHAKE)", "Category", "Public key", "Private key", "Signature"], rows: [["SLH-DSA-*-128s", "1", "32", "64", "7,856"], ["SLH-DSA-*-128f", "1", "32", "64", "17,088"], ["SLH-DSA-*-192s", "3", "48", "96", "16,224"], ["SLH-DSA-*-192f", "3", "48", "96", "35,664"], ["SLH-DSA-*-256s", "5", "64", "128", "29,792"], ["SLH-DSA-*-256f", "5", "64", "128", "49,856"]] },
      seenIn: "Long-lived roots of trust and firmware, where signature size matters less than conservative assumptions.", related: ["ml-dsa", "lms", "xmss"], sources: [NIST.fips205, NIST.pqc] },
    { id: "fn-dsa", name: "FN-DSA", aka: ["Falcon", "FIPS 206", "Falcon-512", "Falcon-1024"], kind: "Signature", family: "Post-quantum",
      status: "Selected by NIST in 2022; the standard (FIPS 206) is being drafted. Check the NIST project page for its current status.", standard: NIST.pqc, risk: "resistant",
      riskText: "Lattice-based (NTRU lattices). No efficient quantum attack is known. Harder to implement safely than ML-DSA because signing uses floating-point Gaussian sampling.",
      summary: "A compact lattice signature: much smaller public keys and signatures than ML-DSA, at the cost of a more delicate implementation.",
      params: { cols: ["Parameter set", "Category", "Public key", "Signature (approx.)"], rows: [["Falcon-512", "1", "897", "666"], ["Falcon-1024", "5", "1,793", "1,280"]] },
      related: ["ml-dsa", "slh-dsa"], sources: [NIST.pqc] },
    { id: "hqc", name: "HQC", aka: ["Hamming Quasi-Cyclic"], kind: "Key encapsulation", family: "Post-quantum",
      status: "Selected in March 2025 as a backup to ML-KEM. NIST plans a draft standard, then a final one; not yet a FIPS.", standard: NIST.ir8545, risk: "resistant",
      riskText: "Code-based (quasi-cyclic codes), deliberately a different mathematical basis from ML-KEM so that one break does not take out both.",
      summary: "A code-based key-encapsulation mechanism chosen as a second, non-lattice option for key establishment. Larger keys and ciphertexts than ML-KEM.",
      related: ["ml-kem"], sources: [NIST.ir8545, NIST.pqc] },
    { id: "x25519mlkem768", name: "X25519MLKEM768", aka: ["X25519MLKEM", "X25519 ML-KEM-768", "X25519Kyber768", "hybrid key exchange", "0x11EC"], kind: "Hybrid key exchange", family: "Hybrid",
      status: "IETF draft, widely deployed. TLS group code point 0x11EC.", standard: TLS_MLKEM, risk: "resistant",
      riskText: "The shared secret combines X25519 and ML-KEM-768. An attacker has to break both, so it stays safe against a quantum computer while keeping the classical security of X25519 if ML-KEM were ever broken.",
      summary: "The TLS 1.3 key-exchange group that makes a connection quantum-safe today. It replaced the earlier experimental X25519Kyber768Draft00.",
      params: { cols: ["Message", "Size", "Made of"], rows: [["Client key share", "1,216", "ML-KEM-768 encapsulation key (1,184) + X25519 public key (32)"], ["Server key share", "1,120", "ML-KEM-768 ciphertext (1,088) + X25519 public key (32)"], ["Shared secret", "64", "ML-KEM shared secret (32) + X25519 shared secret (32)"]] },
      seenIn: "Current Chrome, Edge, Firefox and Safari releases offer it by default. The strip at the top of every Morrow view shows whether your own connection to Morrow used it.", related: ["ml-kem", "x25519"], sources: [TLS_MLKEM, NIST.fips203, RFC(7748, "Elliptic Curves for Security (X25519)")] },
    { id: "lms", name: "LMS", aka: ["Leighton-Micali", "HSS", "LMS/HSS", "SP 800-208"], kind: "Signature", family: "Post-quantum",
      status: "Approved by NIST in SP 800-208 (2020) for limited uses such as firmware signing.", standard: NIST.sp800208, risk: "resistant",
      riskText: "Hash-based, so quantum computers only weaken it generically through the hash. It is stateful: reusing a one-time key breaks security, so the signer must track state.",
      summary: "A stateful hash-based signature scheme. Small keys, fast verification, a fixed number of signatures per key.",
      params: { cols: ["Item", "Size"], rows: [["Public key (SHA-256, n = 32)", "56"], ["Signature", "Depends on tree height and Winternitz parameter"]] },
      related: ["xmss", "slh-dsa"], sources: [NIST.sp800208, RFC(8554, "Leighton-Micali Hash-Based Signatures")] },
    { id: "xmss", name: "XMSS", aka: ["XMSS^MT", "eXtended Merkle Signature Scheme"], kind: "Signature", family: "Post-quantum",
      status: "Approved by NIST in SP 800-208 (2020) for limited uses such as firmware signing.", standard: NIST.sp800208, risk: "resistant",
      riskText: "Hash-based and stateful, like LMS: secure against quantum computers as long as no one-time key is ever reused.",
      summary: "A stateful hash-based signature scheme built on Merkle trees, with a multi-tree variant (XMSS^MT) for more signatures per key.",
      related: ["lms", "slh-dsa"], sources: [NIST.sp800208, RFC(8391, "XMSS: eXtended Merkle Signature Scheme")] }
  ];
  [2048, 3072, 4096].forEach(function (bits) {
    A.push({ id: "rsa-" + bits, name: "RSA-" + bits, aka: bits === 2048 ? ["RSA", "rsaEncryption", "RSA 2048", "sha256WithRSAEncryption"] : ["RSA " + bits], kind: "Signature", family: "Classical",
      status: bits === 2048 ? "Approved today; proposed deprecated after 2030 and disallowed after 2035 (NIST IR 8547 draft)." : "Approved today; proposed disallowed after 2035 (NIST IR 8547 draft).",
      standard: NIST.fips1865, risk: "broken",
      riskText: SHOR + (bits === 2048 ? " A 2025 estimate puts factoring RSA-2048 at under a million noisy qubits running for less than a week." : " A larger key raises the cost for a quantum computer only modestly.") + " " + IR8547,
      summary: "RSA with a " + bits + "-bit modulus, used for signatures (certificates, code signing) and, in older protocols, key transport.",
      params: { cols: ["Item", "Value"], rows: [["Modulus", bits + " bits"], ["Signature", (bits / 8) + " bytes"], ["Classical security strength", bits === 2048 ? "112 bits" : bits === 3072 ? "128 bits" : "Between 128 and 192 bits"], ["Quantum security", "None against a large fault-tolerant quantum computer"]] },
      seenIn: "Most TLS certificates on the web, code-signing certificates, SSH host keys, S/MIME.", related: ["ml-dsa", "ml-kem", "ecdsa-p256"],
      sources: [NIST.fips1865, NIST.sp80056b, NIST.sp80057, NIST.ir8547].concat(bits === 2048 ? [GIDNEY] : []) });
  });
  A.push(
    { id: "ecdsa-p256", name: "ECDSA P-256", aka: ["ECDSA", "P-256", "secp256r1", "prime256v1", "ecdsa-with-SHA256", "NIST P-256"], kind: "Signature", family: "Classical",
      status: "Approved today; proposed disallowed after 2035 (NIST IR 8547 draft).", standard: NIST.fips1865, risk: "broken",
      riskText: SHOR + " Elliptic-curve keys need fewer qubits to break than RSA keys of the same classical strength. " + IR8547,
      summary: "Elliptic-curve signatures on the NIST P-256 curve. The most common signature algorithm in modern TLS certificates after RSA.",
      params: { cols: ["Item", "Size"], rows: [["Public key (uncompressed)", "65"], ["Signature (r, s)", "64 (about 70-72 DER-encoded)"], ["Classical security strength", "128 bits"]] },
      related: ["ecdsa-p384", "ed25519", "ml-dsa"], sources: [NIST.fips1865, NIST.sp800186, NIST.ir8547] },
    { id: "ecdsa-p384", name: "ECDSA P-384", aka: ["P-384", "secp384r1", "NIST P-384", "ecdsa-with-SHA384"], kind: "Signature", family: "Classical",
      status: "Approved today; proposed disallowed after 2035 (NIST IR 8547 draft).", standard: NIST.fips1865, risk: "broken", riskText: SHOR + " " + IR8547,
      summary: "Elliptic-curve signatures on the NIST P-384 curve, common for CA roots and government systems.",
      params: { cols: ["Item", "Size"], rows: [["Public key (uncompressed)", "97"], ["Signature (r, s)", "96"], ["Classical security strength", "192 bits"]] },
      related: ["ecdsa-p256", "ml-dsa"], sources: [NIST.fips1865, NIST.sp800186, NIST.ir8547] },
    { id: "ed25519", name: "Ed25519", aka: ["EdDSA", "Curve25519 signature", "ssh-ed25519"], kind: "Signature", family: "Classical",
      status: "Approved by NIST in FIPS 186-5 (2023); proposed disallowed after 2035 (NIST IR 8547 draft).", standard: NIST.fips1865, risk: "broken", riskText: SHOR + " " + IR8547,
      summary: "Edwards-curve signatures over Curve25519. Fast, deterministic, hard to misuse. Default for new SSH keys.",
      params: { cols: ["Item", "Size"], rows: [["Public key", "32"], ["Private key", "32"], ["Signature", "64"], ["Classical security strength", "About 128 bits"]] },
      related: ["x25519", "ml-dsa"], sources: [NIST.fips1865, RFC(8032, "Edwards-Curve Digital Signature Algorithm (EdDSA)"), NIST.ir8547] },
    { id: "x25519", name: "X25519", aka: ["Curve25519", "ECDH X25519", "x25519 key exchange"], kind: "Key agreement", family: "Classical",
      status: "Widely used; Curve25519 is specified by NIST in SP 800-186. Proposed disallowed after 2035 (NIST IR 8547 draft).", standard: RFC(7748, "Elliptic Curves for Security"), risk: "broken",
      riskText: SHOR + " Key agreement is where harvest now, decrypt later bites: a recorded handshake can be decrypted years later. " + IR8547,
      summary: "Elliptic-curve Diffie-Hellman over Curve25519. The default TLS 1.3 key exchange before hybrids, and still what a connection falls back to when either side lacks ML-KEM.",
      params: { cols: ["Item", "Size"], rows: [["Public key", "32"], ["Shared secret", "32"], ["Classical security strength", "About 128 bits"]] },
      seenIn: "A TLS connection that reports X25519 is not quantum-safe; one that reports X25519MLKEM768 is.", related: ["x25519mlkem768", "ml-kem", "ecdh-p256"], sources: [RFC(7748, "Elliptic Curves for Security"), NIST.sp800186, NIST.ir8547] },
    { id: "ecdh-p256", name: "ECDH P-256", aka: ["ECDHE", "secp256r1 key exchange", "P-256 ECDH"], kind: "Key agreement", family: "Classical",
      status: "Approved today (SP 800-56A Rev. 3); proposed disallowed after 2035 (NIST IR 8547 draft).", standard: NIST.sp80056a, risk: "broken", riskText: SHOR + " " + IR8547,
      summary: "Elliptic-curve Diffie-Hellman on the NIST P-256 curve, the usual key exchange where FIPS-validated cryptography is required.",
      params: { cols: ["Item", "Size"], rows: [["Public key (uncompressed)", "65"], ["Shared secret", "32"], ["Classical security strength", "128 bits"]] },
      related: ["x25519", "ml-kem"], sources: [NIST.sp80056a, NIST.sp800186, NIST.ir8547] }
  );
  [128, 256].forEach(function (bits) {
    A.push({ id: "aes-" + bits, name: "AES-" + bits, aka: bits === 128 ? ["AES", "AES-128-GCM", "AES128"] : ["AES-256-GCM", "AES256"], kind: "Block cipher", family: "Symmetric",
      status: "Approved, and remains approved after the post-quantum transition (NIST IR 8547 draft).", standard: NIST.fips197, risk: bits === 128 ? "weakened" : "resistant",
      riskText: bits === 128 ? "Grover's algorithm in theory halves the effective key length, but it parallelises badly and needs a long serial computation. NIST considers AES-128 adequate and uses it as the reference point for security category 1."
        : "Grover's algorithm leaves an effective strength far beyond any foreseeable attack. Required by some national guidance (for example CNSA 2.0) for the most sensitive data.",
      summary: "The Advanced Encryption Standard with a " + bits + "-bit key, used for the bulk encryption in TLS, disks and files.",
      params: { cols: ["Item", "Value"], rows: [["Key", bits + " bits"], ["Block", "128 bits"], ["Classical security strength", bits + " bits"]] },
      related: [bits === 128 ? "aes-256" : "aes-128", "sha-256", "ml-kem"], sources: [NIST.fips197, NIST.sp80057, NIST.ir8547] });
  });
  A.push({ id: "sha-256", name: "SHA-256", aka: ["SHA2", "SHA-2", "SHA256"], kind: "Hash function", family: "Symmetric",
    status: "Approved, and remains approved after the post-quantum transition (NIST IR 8547 draft).", standard: NIST.fips1804, risk: "weakened",
    riskText: "Quantum search gives at best a modest speed-up against preimages and collisions, far from practical. Hash-based signatures such as SLH-DSA rely on functions like it.",
    summary: "The SHA-2 hash function with a 256-bit output. Used in certificates, signatures, git object names, and as a building block for SLH-DSA and LMS.",
    params: { cols: ["Item", "Value"], rows: [["Output", "32 bytes"], ["Classical collision resistance", "128 bits"]] },
    related: ["slh-dsa", "lms", "aes-256"], sources: [NIST.fips1804, NIST.sp80057, NIST.ir8547] });

  /* The internet's cryptography, dated. Each event links to the document that dates it. */
  var HISTORY = [
    { y: 1976, d: "Diffie and Hellman publish public-key key agreement.", a: ["x25519", "ecdh-p256"], src: { label: "Diffie, Hellman: New Directions in Cryptography (IEEE Trans. Inf. Theory, 1976)", href: "https://ee.stanford.edu/~hellman/publications/24.pdf" } },
    { y: 1977, d: "Rivest, Shamir and Adleman describe RSA (published 1978).", a: ["rsa-2048"], src: { label: "RSA: A Method for Obtaining Digital Signatures and Public-Key Cryptosystems (CACM, 1978)", href: "https://people.csail.mit.edu/rivest/Rsapaper.pdf" } },
    { y: 1985, d: "Koblitz and Miller independently propose elliptic-curve cryptography.", a: ["ecdsa-p256", "ecdh-p256"], src: { label: "NIST SP 800-186 (background and curves)", href: "https://csrc.nist.gov/pubs/sp/800/186/final" } },
    { y: 1994, d: "Shor shows a quantum computer could factor and take discrete logarithms efficiently: RSA and elliptic curves are breakable in principle.", a: ["rsa-2048", "ecdsa-p256", "x25519"], src: { label: "Shor: Algorithms for quantum computation (FOCS 1994), arXiv:quant-ph/9508027", href: "https://arxiv.org/abs/quant-ph/9508027" } },
    { y: 1996, d: "Grover's search algorithm: a square-root speed-up against symmetric keys, which is why AES-256 stays strong.", a: ["aes-128", "aes-256"], src: { label: "Grover: A fast quantum mechanical algorithm for database search, arXiv:quant-ph/9605043", href: "https://arxiv.org/abs/quant-ph/9605043" } },
    { y: 1999, d: "TLS 1.0 published, succeeding SSL 3.0.", a: [], src: RFC(2246, "The TLS Protocol Version 1.0") },
    { y: 2001, d: "AES becomes a US federal standard.", a: ["aes-128", "aes-256"], src: NIST.fips197 },
    { y: 2002, d: "SHA-256 standardised as part of SHA-2.", a: ["sha-256"], src: NIST.fips1804 },
    { y: 2008, d: "TLS 1.2 published; it remains the most common fallback version.", a: [], src: RFC(5246, "The TLS Protocol Version 1.2") },
    { y: 2016, d: "X25519 specified for the internet; NIST opens its call for post-quantum algorithms.", a: ["x25519"], src: RFC(7748, "Elliptic Curves for Security") },
    { y: 2018, d: "TLS 1.3 published: forward secrecy only, no RSA key transport.", a: ["x25519"], src: RFC(8446, "The TLS Protocol Version 1.3") },
    { y: 2020, d: "NIST approves stateful hash-based signatures LMS and XMSS for limited uses.", a: ["lms", "xmss"], src: NIST.sp800208 },
    { y: 2022, d: "NIST selects Kyber, Dilithium, Falcon and SPHINCS+ for standardisation.", a: ["ml-kem", "ml-dsa", "fn-dsa", "slh-dsa"], src: NIST.pqc },
    { y: 2024, d: "FIPS 203, 204 and 205 published on 13 August: ML-KEM, ML-DSA and SLH-DSA are final. Browsers move to the X25519MLKEM768 hybrid group.", a: ["ml-kem", "ml-dsa", "slh-dsa", "x25519mlkem768"], src: NIST.fips203 },
    { y: 2024, d: "NIST IR 8547 draft proposes retiring quantum-vulnerable public-key algorithms: deprecated after 2030, disallowed after 2035.", a: ["rsa-2048", "ecdsa-p256", "x25519"], src: NIST.ir8547 },
    { y: 2025, d: "HQC selected as a code-based backup to ML-KEM.", a: ["hqc"], src: NIST.ir8545 },
    { y: 2025, d: "A new estimate: RSA-2048 factored with under a million noisy qubits in under a week.", a: ["rsa-2048"], src: GIDNEY }
  ];

  var RISK_LABEL = { broken: "Broken by a quantum computer", weakened: "Weakened, still adequate", resistant: "Designed to resist" };
  var norm = function (s) { return String(s).toLowerCase().replace(/[\s_\-+./()^]/g, ""); };
  var INDEX = {};
  A.forEach(function (a) { [a.id, a.name].concat(a.aka).forEach(function (n) { var k = norm(n); if (!(k in INDEX)) INDEX[k] = a.id; }); });
  window.MORROW_REF = {
    algorithms: A, history: HISTORY, riskLabel: RISK_LABEL,
    get: function (id) { for (var i = 0; i < A.length; i++) if (A[i].id === id) return A[i]; return null; },
    find: function (q) { var id = INDEX[norm(q)]; return id ? this.get(id) : null; }
  };
})();
