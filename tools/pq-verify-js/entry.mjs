// The browser verifier's cryptography, bundled into one file (see build.mjs). Verification only:
// nothing here can sign, and nothing here talks to the network.
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha512 } from "@noble/hashes/sha2.js";

globalThis.MorrowPQ = Object.freeze({
  library: "@noble/post-quantum 0.7.1, @noble/curves 2.4.0, @noble/hashes 2.4.0",
  // FIPS 204 ML-DSA-65, pure (no pre-hash), with a context string.
  mlDsa65Verify: (sig, msg, publicKey, context) => ml_dsa65.verify(sig, msg, publicKey, { context }),
  // RFC 8032 strict verification (zip215: false), the same acceptance rule as OpenSSL on the server.
  ed25519Verify: (sig, msg, publicKey) => ed25519.verify(sig, msg, publicKey, { zip215: false }),
  sha512Create: () => sha512.create(),
});
