/* Evidence packs on the vendor report (/vendors/r/<token>): services/vendor_evidence.py.
 *
 * For every vendor in the buyer's private report that is not quantum-safe, an "Evidence pack" action:
 * the server signs the pack (Ed25519 + ML-DSA-65, context morrow.vendor-evidence.v1), this browser
 * checks both signatures against /.well-known/morrow-proof-keys.json with the vendored verifier
 * (/ui/vendor/morrow-pq-verify.js), and the seal lands only when they verify. Then: the ZIP, the
 * proposed addendum and a ticket to copy, a prefilled GitHub issue link and the Jira CSV.
 *
 * instrument.js announces each paint of the report with "morrow:vendor-report", detail
 * { report, token, api }. Nothing here sends anything to a vendor or to GitHub: the GitHub link only
 * opens GitHub's own new-issue page in the buyer's browser. Vendors stay in the report's order
 * (worst first inside this private report only).
 */
(function () {
  "use strict";
  function I() { return window.MorrowIns; }
  var enc = new TextEncoder();
  var STATE = {};        // token|domain -> { phase, data, error, landed }
  var SHELF = null, KEYS = null, PQ = null;
  var CHOICE = { data: lsGet("morrow_vendor_data", ""), by: "" };
  var REDUCED = !!(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches);

  function lsGet(k, d) { try { var v = localStorage.getItem(k); return v == null ? d : v; } catch (e) { return d; } }
  function lsSet(k, v) { try { localStorage.setItem(k, v); } catch (e) { /* private mode */ } }
  function unb64(s) { var b = atob(String(s || "")), out = new Uint8Array(b.length); for (var i = 0; i < b.length; i++) out[i] = b.charCodeAt(i); return out; }
  function canonical(v) {
    if (v === null || typeof v !== "object") return JSON.stringify(v);
    if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
    return "{" + Object.keys(v).sort().map(function (k) { return JSON.stringify(k) + ":" + canonical(v[k]); }).join(",") + "}";
  }
  function qs() {
    var p = [];
    if (CHOICE.data) p.push("data=" + encodeURIComponent(CHOICE.data));
    if (CHOICE.by) p.push("by=" + encodeURIComponent(CHOICE.by));
    return p.length ? "?" + p.join("&") : "";
  }
  function key(tok, d) { return tok + "|" + d; }

  /* ── the verifier, the keys and the kinds of data: loaded once, on first use ── */
  function verifier() {
    if (window.MorrowPQ) return Promise.resolve(window.MorrowPQ);
    if (PQ) return PQ;
    PQ = new Promise(function (resolve, reject) {
      var s = document.createElement("script");
      s.src = "/ui/vendor/morrow-pq-verify.js"; s.async = true;
      s.onload = function () { if (window.MorrowPQ) resolve(window.MorrowPQ); else reject(new Error("the verifier did not load")); };
      s.onerror = function () { PQ = null; reject(new Error("the verifier did not load")); };
      document.head.appendChild(s);
    });
    return PQ;
  }
  function keys() {
    if (KEYS) return KEYS;
    KEYS = fetch("/.well-known/morrow-proof-keys.json", { cache: "no-store", credentials: "omit" })
      .then(function (r) { if (!r.ok) throw new Error("the published keys did not load"); return r.json(); })
      .catch(function (e) { KEYS = null; throw e; });
    return KEYS;
  }
  function shelf() {
    if (SHELF) return SHELF;
    SHELF = I().getJSON("/api/public/shelf-life").catch(function () { return { categories: [] }; });
    return SHELF;
  }
  function check(envelope, published, MorrowPQ) {
    var doc = envelope.document || {}, sigs = envelope.signatures || [], byKid = {};
    (published.keys || []).forEach(function (k) { byKid[k.kid] = k; });
    var head = enc.encode(String(doc.signing_context || "") + "\n"), body = enc.encode(canonical(doc));
    var msg = new Uint8Array(head.length + body.length); msg.set(head, 0); msg.set(body, head.length);
    var results = sigs.map(function (s) {
      var k = byKid[s.kid], ok = false;
      if (k && k.alg === s.alg) {
        try {
          if (s.alg === "Ed25519") ok = MorrowPQ.ed25519Verify(unb64(s.signature), msg, unb64(k.public_key));
          else if (s.alg === "ML-DSA-65") ok = MorrowPQ.mlDsa65Verify(unb64(s.signature), msg, unb64(k.public_key), new Uint8Array(0));
        } catch (e) { ok = false; }
      }
      return { alg: s.alg, ok: !!ok };
    });
    return { valid: results.length > 0 && results.every(function (r) { return r.ok; }) && doc.format === "morrow.vendor-evidence/v1", results: results };
  }

  /* ── the top panel: kind of data, target date, all packs at once ── */
  function topPanel(R, api, tok) {
    var M = I(), n = needing(R).length;
    var box = document.getElementById("vr-packs");
    if (!box) {
      box = document.createElement("div"); box.id = "vr-packs";
      var top = document.getElementById("vr-top"); if (!top) return;
      top.parentNode.insertBefore(box, top.nextSibling);
    }
    if (!n) { box.innerHTML = ""; return; }
    if (box.getAttribute("data-n") === String(n) && box.firstChild) { allLinks(api); return; }
    box.setAttribute("data-n", String(n));
    box.innerHTML = M.panel("", "Evidence packs",
      '<p class="ev-lede">' + (n === 1 ? "1 vendor is" : n + " vendors are") + " not quantum-safe. For each, Morrow can sign what it measured into a pack you can send, with a proposed contract addendum and a ready-made ticket.</p>" +
      '<div class="ev-choose">' +
      '<label class="ev-field"><span>Kind of data they handle</span><select class="i-btn" id="ev-data"><option value="">Not sure</option></select></label>' +
      '<label class="ev-field"><span>Target date for the addendum <small>(optional)</small></span><input class="i-btn" type="date" id="ev-by"></label>' +
      "</div>" +
      '<p class="i-row ev-actions"><button type="button" class="i-btn solid" id="ev-all">Download all evidence packs</button><a class="i-btn" id="ev-jira" href="#">Jira CSV, all vendors</a></p>' +
      '<div class="ev-moment" id="ev-all-m" role="status" aria-live="polite"></div>' +
      '<p class="i-fine">"Not sure" uses Shelf-Life\'s assumed default. Without a date, the addendum proposes one from the deadline. Morrow sends nothing to your vendors.</p>', { ch: "grade" });
    shelf().then(function (S) {
      var sel = document.getElementById("ev-data"); if (!sel) return;
      (S.categories || []).forEach(function (c) { var o = document.createElement("option"); o.value = c.id; o.textContent = c.label; sel.appendChild(o); });
      sel.value = CHOICE.data; if (sel.value !== CHOICE.data) { CHOICE.data = ""; sel.value = ""; }
      allLinks(api);
    });
    var sel = document.getElementById("ev-data"), by = document.getElementById("ev-by");
    by.value = CHOICE.by;
    by.min = new Date().toISOString().slice(0, 10);
    sel.addEventListener("change", function () { CHOICE.data = sel.value; lsSet("morrow_vendor_data", sel.value); changed(tok); allLinks(api); });
    by.addEventListener("change", function () { CHOICE.by = by.value; changed(tok); allLinks(api); });
    document.getElementById("ev-all").addEventListener("click", function () { downloadAll(api, n, this); });
    allLinks(api);
  }
  function allLinks(api) { var j = document.getElementById("ev-jira"); if (j) j.href = api + "/tickets.csv" + qs(); }
  function changed(tok) {
    // A different kind of data or date is a different pack: the open ones are made again on request.
    Object.keys(STATE).forEach(function (k) { if (k.indexOf(tok + "|") === 0 && STATE[k].phase === "ready") STATE[k] = { phase: "stale" }; });
    document.querySelectorAll(".ev-row").forEach(function (tr) { var d = tr.getAttribute("data-ev"); if (d) paintRow(tr, tok, d); });
  }
  function needing(R) { return (R.vendors || []).filter(function (v) { return v.grade && v.exposed; }); }

  function steps(phase, extra) {
    var order = ["signing", "checking", "ready"];
    var at = order.indexOf(phase);
    var label = { signing: "Signing", checking: "Checking both signatures in this browser", ready: "Signed and ready" };
    return '<ol class="ev-steps">' + order.map(function (p, i) {
      return '<li data-s="' + (i < at || phase === "ready" ? "done" : i === at ? "now" : "next") + '">' + label[p] + (i === at && phase !== "ready" ? "…" : "") + "</li>";
    }).join("") + "</ol>" + (extra || "");
  }
  function seal(landing, text) {
    return '<span class="ev-seal' + (landing && !REDUCED ? " is-landing" : "") + '"><span class="ev-seal-mark" aria-hidden="true">&#10003;</span><span class="ev-seal-t">' + I().esc(text) + "</span></span>";
  }

  function downloadAll(api, n, btn) {
    var m = document.getElementById("ev-all-m"), M = I();
    btn.setAttribute("aria-busy", "true"); btn.disabled = true;
    m.innerHTML = steps("signing", '<p class="i-fine">Signing ' + n + " pack" + (n === 1 ? "" : "s") + "…</p>");
    fetch(api + "/evidence.zip" + qs(), { credentials: "same-origin", cache: "no-store" }).then(function (r) {
      if (!r.ok) return r.json().catch(function () { return {}; }).then(function (b) { throw new Error(b.detail || ("HTTP " + r.status)); });
      var cd = r.headers.get("Content-Disposition") || "", name = (cd.match(/filename="([^"]+)"/) || [])[1] || "morrow-evidence.zip";
      return r.blob().then(function (b) { return { blob: b, name: name }; });
    }).then(function (got) {
      var href = URL.createObjectURL(got.blob);
      m.innerHTML = seal(true, "Signed and ready") + ' <a class="i-btn" id="ev-all-save" href="' + href + '" download="' + M.esc(got.name) + '">Save ' + M.esc(got.name) + "</a>";
      var a = document.getElementById("ev-all-save"); if (a) a.click();
    }).catch(function (e) {
      m.innerHTML = '<p class="i-status" data-tone="bad">' + M.esc(e.message) + "</p>";
    }).finally(function () { btn.removeAttribute("aria-busy"); btn.disabled = false; });
  }

  /* ── one vendor ── */
  function generate(tok, api, d, tr) {
    var k = key(tok, d), st = { phase: "signing", open: true };
    STATE[k] = st; paintRow(tr, tok, d);
    I().getJSON(api + "/evidence/" + encodeURIComponent(d) + qs(), { cache: "no-store" }).then(function (P) {
      if (STATE[k] !== st) return;
      st.data = P; st.phase = "checking"; paintRow(currentRow(d) || tr, tok, d);
      return Promise.all([verifier(), keys()]).then(function (got) {
        var out = check(P.envelope, got[1], got[0]);
        if (STATE[k] !== st) return;
        st.browser = out; st.phase = "ready"; st.landing = true;
        paintRow(currentRow(d) || tr, tok, d);
        st.landing = false;
      }, function (e) {
        if (STATE[k] !== st) return;
        st.browser = { valid: false, error: e.message }; st.phase = "ready"; st.landing = false;
        paintRow(currentRow(d) || tr, tok, d);
      });
    }).catch(function (e) {
      if (STATE[k] !== st) return;
      st.phase = "error"; st.error = e.message; paintRow(currentRow(d) || tr, tok, d);
    });
  }
  function currentRow(d) { return document.querySelector('.ev-row[data-ev="' + (window.CSS && CSS.escape ? CSS.escape(d) : d) + '"]'); }

  function paintRow(tr, tok, d) {
    if (!tr) return;
    var M = I(), esc = M.esc, st = STATE[key(tok, d)] || { phase: "idle" }, cell = tr.firstChild;
    var api = tr.getAttribute("data-api");
    if (st.phase === "idle" || st.phase === "stale") {
      cell.innerHTML = '<div class="ev-box"><p>' + (st.phase === "stale" ? "Your choices changed. " : "") + "Sign what Morrow measured about " + esc(d) + ' into a pack: the dated checks and their links, the deadline for your kind of data, how Morrow measures, a proposed addendum and a ticket.</p><p class="i-row"><button type="button" class="i-btn solid" data-ev-go>' + (st.phase === "stale" ? "Make the pack again" : "Make the evidence pack") + "</button></p></div>";
      cell.querySelector("[data-ev-go]").addEventListener("click", function () { generate(tok, api, d, tr); });
      return;
    }
    if (st.phase === "error") {
      cell.innerHTML = '<div class="ev-box"><p class="i-status" data-tone="bad" role="alert">' + esc(st.error) + '</p><p class="i-row"><button type="button" class="i-btn" data-ev-go>Try again</button></p></div>';
      cell.querySelector("[data-ev-go]").addEventListener("click", function () { generate(tok, api, d, tr); });
      return;
    }
    if (st.phase !== "ready") {
      cell.innerHTML = '<div class="ev-box" role="status" aria-live="polite">' + steps(st.phase) + "</div>";
      return;
    }
    var P = st.data, dl = P.deadline || {}, td = P.target_date || {}, b = st.browser || {};
    var sealText = b.valid ? "Signed and ready" : "Signed by Morrow";
    var checked = b.valid ? "Ed25519 and ML-DSA-65 both verified in this browser against the published keys."
      : b.error ? "This browser could not check the signatures (" + b.error + "). The server checked them before handing the pack out; verify.py in the pack checks them offline."
      : "This browser could not verify every signature. Use verify.py in the pack to check it offline before you rely on it.";
    var repo = lsGet("morrow_vendor_repo", "");
    cell.innerHTML = '<div class="ev-box ev-ready">' +
      '<div class="ev-head" role="status" aria-live="polite">' + seal(st.landing, sealText) + '<span class="i-fine">' + esc(checked) + "</span></div>" +
      '<p class="ev-deadline">' + esc(dl.sentence || "") + "</p>" +
      '<p class="i-fine">Target date in the addendum: <b>' + esc(td.date || "") + "</b>. " + esc(td.why || "") + "</p>" +
      '<p class="i-row"><a class="i-btn solid" href="' + esc(api + "/evidence/" + encodeURIComponent(d) + ".zip" + qs()) + '" download="' + esc(P.zip_name || "") + '">Download evidence pack</a>' +
      '<button type="button" class="i-btn" data-ev-copy="addendum">Copy addendum</button><button type="button" class="i-btn" data-ev-copy="ticket">Copy ticket</button></p>' +
      '<p class="ev-notice">' + esc((P.addendum || {}).notice || "") + ' <span class="i-fine">Addendum template v' + esc((P.addendum || {}).version || "") + ", " + esc((P.addendum || {}).date || "") + ".</span></p>" +
      '<div class="ev-gh"><label class="ev-field"><span>Your GitHub repository</span><input class="i-btn" data-ev-repo placeholder="owner/name" autocomplete="off" spellcheck="false" value="' + esc(repo) + '"></label>' +
      '<a class="i-btn" data-ev-gh target="_blank" rel="noopener noreferrer" href="#">Open a GitHub issue</a></div>' +
      '<p class="i-fine">The GitHub link opens GitHub\'s new-issue page with the ticket filled in; Morrow makes no call to GitHub and keeps no credentials. The pack: ' + esc((P.files || []).join(", ")) + ".</p></div>";
    cell.querySelectorAll("[data-ev-copy]").forEach(function (btn) {
      btn.addEventListener("click", function () { M.copy(btn.getAttribute("data-ev-copy") === "addendum" ? P.addendum.markdown : P.ticket.markdown, btn); });
    });
    var input = cell.querySelector("[data-ev-repo]"), gh = cell.querySelector("[data-ev-gh]");
    function ghLink() {
      var v = String(input.value || "").trim().replace(/^https:\/\/github\.com\//, "").replace(/\/+$/, ""), ok = /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9._-]{1,100}$/.test(v);
      gh.setAttribute("aria-disabled", ok ? "false" : "true");
      gh.href = ok ? api + "/evidence/" + encodeURIComponent(d) + "/github" + (qs() ? qs() + "&" : "?") + "repo=" + encodeURIComponent(v) : "#";
      if (ok) lsSet("morrow_vendor_repo", v);
    }
    input.addEventListener("input", ghLink);
    gh.addEventListener("click", function (e) { if (gh.getAttribute("aria-disabled") === "true") { e.preventDefault(); input.focus(); } });
    ghLink();
  }

  /* ── each paint of the report ── */
  document.addEventListener("morrow:vendor-report", function (e) {
    var det = e.detail || {}, R = det.report || {}, tok = det.token, api = det.api, M = I();
    if (!M || !tok) return;
    topPanel(R, api, tok);
    var list = document.getElementById("vr-list"); if (!list) return;
    var cols = list.querySelector("thead tr") ? list.querySelector("thead tr").children.length : 6;
    needing(R).forEach(function (v) {
      var row = list.querySelector('tr[data-d="' + (window.CSS && CSS.escape ? CSS.escape(v.domain) : v.domain) + '"]');
      if (!row) return;
      var cell = row.lastElementChild, k = key(tok, v.domain), open = !!(STATE[k] && STATE[k].open);
      var b = document.createElement("button");
      b.type = "button"; b.className = "i-btn"; b.textContent = "Evidence pack";
      b.setAttribute("aria-expanded", open ? "true" : "false");
      var id = "ev-" + v.domain.replace(/[^a-z0-9]+/gi, "-");
      b.setAttribute("aria-controls", id);
      cell.classList.add("ev-cell"); cell.appendChild(b);
      var after = row.nextElementSibling && row.nextElementSibling.classList.contains("vr-note") ? row.nextElementSibling : row;
      var tr = document.createElement("tr");
      tr.className = "ev-row"; tr.id = id; tr.hidden = !open;
      tr.setAttribute("data-ev", v.domain); tr.setAttribute("data-api", api);
      tr.innerHTML = '<td colspan="' + cols + '"></td>';
      after.parentNode.insertBefore(tr, after.nextSibling);
      if (open) paintRow(tr, tok, v.domain);
      b.addEventListener("click", function () {
        var s = STATE[k] || (STATE[k] = { phase: "idle" });
        s.open = tr.hidden; tr.hidden = !tr.hidden; b.setAttribute("aria-expanded", String(!tr.hidden));
        if (!tr.hidden) {
          if (s.phase === "idle") generate(tok, api, v.domain, tr); else paintRow(tr, tok, v.domain);
          STATE[k].open = true;
        }
      });
    });
  });

  window.MorrowEvidence = { check: check, canonical: canonical };
})();
