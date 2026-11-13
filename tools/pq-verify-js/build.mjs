// npm ci && npm run build  ->  backend/static/vendor/morrow-pq-verify.js
// The output is committed, so the server never needs Node; rebuild it when a version above changes.
import { build } from "esbuild";

await build({
  entryPoints: ["entry.mjs"],
  outfile: "../../backend/static/vendor/morrow-pq-verify.js",
  bundle: true,
  format: "iife",
  platform: "browser",
  target: ["es2020"],
  minify: false,
  legalComments: "inline",
  banner: { js: "/* morrow-pq-verify: built by tools/pq-verify-js from @noble/post-quantum 0.7.1, @noble/curves 2.4.0 and @noble/hashes 2.4.0 (MIT, Paul Miller). Do not edit; rebuild. */" },
});
