/* The quantum-safe proof page (/r/<domain>/proof): check both signatures in this browser.
 *
 * Reads the signed envelope (/r/<domain>/proof.json) and the deployment's published keys
 * (/.well-known/morrow-proof-keys.json), rebuilds the signed bytes exactly as
 * services/make_safe.sign_document does (context line + canonical JSON of the document), and
 * verifies Ed25519 and ML-DSA-65 with /ui/vendor/morrow-pq-verify.js. Nothing is sent anywhere.
 */
(function () {
  "use strict";
  var enc = new TextEncoder();
  function $(s) { return document.querySelector(s); }
  function unb64(s) { var b = atob(String(s || "")), out = new Uint8Array(b.length); for (var i = 0; i < b.length; i++) out[i] = b.charCodeAt(i); return out; }
  function canonical(v) {
    if (v === null || typeof v !== "object") return JSON.stringify(v);
    if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
    return "{" + Object.keys(v).sort().map(function (k) { return JSON.stringify(k) + ":" + canonical(v[k]); }).join(",") + "}";
  }
  function getJSON(u) { return fetch(u, { cache: "no-store", credentials: "omit" }).then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status + " from " + u); return r.json(); }); }
  function say(text, tone) { var o = $("#proof-verify-out"); if (!o) return; o.textContent = text; if (tone) o.setAttribute("data-tone", tone); else o.removeAttribute("data-tone"); }

  function check(envelope, published) {
    var doc = envelope.document || {}, sigs = envelope.signatures || [];
    var keys = {}; (published.keys || []).forEach(function (k) { keys[k.kid] = k; });
    var ctx = String(doc.signing_context || "") + "\n";
    var body = enc.encode(canonical(doc)), head = enc.encode(ctx);
    var msg = new Uint8Array(head.length + body.length); msg.set(head, 0); msg.set(body, head.length);
    var results = sigs.map(function (s) {
      var k = keys[s.kid], ok = false;
      if (k && k.alg === s.alg) {
        try {
          if (s.alg === "Ed25519") ok = window.MorrowPQ.ed25519Verify(unb64(s.signature), msg, unb64(k.public_key));
          else if (s.alg === "ML-DSA-65") ok = window.MorrowPQ.mlDsa65Verify(unb64(s.signature), msg, unb64(k.public_key), new Uint8Array(0));
        } catch (e) { ok = false; }
      }
      return { alg: s.alg, kid: s.kid, ok: !!ok, known: !!k };
    });
    return { valid: results.length > 0 && results.every(function (r) { return r.ok; }), results: results };
  }

  function run() {
    var root = $("[data-proof]"); if (!root) return;
    if (!window.MorrowPQ) { say("The verifier did not load. Reload the page, or check offline as described below.", "bad"); return; }
    say("Checking…");
    Promise.all([getJSON(root.getAttribute("data-proof")), getJSON("/.well-known/morrow-proof-keys.json")]).then(function (got) {
      var out = check(got[0], got[1]);
      var parts = out.results.map(function (r) { return r.alg + (r.ok ? " verifies" : r.known ? " does NOT verify" : " uses a key this server does not publish"); });
      say((out.valid ? "Valid: " : "Not valid: ") + parts.join(", ") + ".", out.valid ? "ok" : "bad");
      // The seal answers too, once: verified here, by this browser, or not.
      var seal = document.querySelector(".seal"), ok = $("#seal-ok");
      if (seal) seal.setAttribute("data-verified", out.valid ? "ok" : "bad");
      if (ok) ok.textContent = out.valid ? "Verified in this browser" : "Did not verify in this browser";
    }).catch(function (e) { say("Could not check: " + e.message, "bad"); });
  }

  document.addEventListener("DOMContentLoaded", function () {
    var b = $("#proof-verify"); if (!b) return;
    b.hidden = false;
    b.addEventListener("click", run);
  });
})();
