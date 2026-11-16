/* Your connection, right now: one line on /r/<domain> naming the key exchange this browser and
   Morrow agreed on. Cloudflare, in front of the hosted Morrow, answers /cdn-cgi/trace on this origin
   (connect-src 'self'). That answer also carries the visitor's IP address: only kex= is read, and
   nothing from it is shown beyond the algorithm name, kept or sent anywhere. Where the path does
   not exist (a self-hosted copy, local development) the line stays empty and takes no space.
   instrument.js says the same sentence under the home domain box. */
(function () {
  "use strict";
  var el = document.getElementById("conn-line");
  if (!el || !window.fetch) return;
  fetch("/cdn-cgi/trace", { cache: "no-store", credentials: "omit" })
    .then(function (r) {
      if (!r.ok || (r.headers.get("content-type") || "").indexOf("text/plain") !== 0) throw new Error("none");
      return r.text();
    })
    .then(function (t) {
      var m = /^kex=([A-Za-z0-9_-]{1,40})$/m.exec(t);
      if (!m) return;
      var kex = m[1];
      el.textContent = /mlkem|kyber/i.test(kex)
        ? "You're connected to Morrow with " + kex + " \u2014 quantum-safe key exchange."
        : "You're connected to Morrow with " + kex + " \u2014 classical. Try a current Chrome, Edge, Firefox or Safari.";
    })
    .catch(function () {});
})();
