/* The verify page: a domain's post-quantum signing keys and signatures, and a file checked here.
 *
 * A dropped file is hashed in this browser (SHA-512) and its signature is checked in this browser
 * with ML-DSA-65 (FIPS 204) and Ed25519, using /ui/vendor/morrow-pq-verify.js (@noble/post-quantum
 * 0.7.1, served from this origin). The file is never sent anywhere. When the file is not among the
 * signatures this page already loaded, the page asks Morrow for signatures with that SHA-512: the
 * fingerprint is sent, not the file.
 *
 * The rules are the server's (services/pq_signing.assess) and morrow-sign's: both signatures must
 * verify; a retired key's signature counts only when dated before the retirement; a revoked key's
 * only when Morrow recorded it before the time the key stopped being trusted; a withdrawn signature
 * never does.
 */
(function () {
  "use strict";
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var enc = new TextEncoder();
  var CTX = enc.encode("morrow-signature/1");
  var DEPTHS = ["plain", "standard", "expert"];
  var LS = {
    get: function (k, d) { try { var v = localStorage.getItem(k); return v == null ? d : v; } catch (e) { return d; } },
    set: function (k, v) { try { localStorage.setItem(k, v); } catch (e) { /* private mode */ } }
  };
  function esc(v) {
    return String(v == null ? "" : v).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function param(k) { return new URLSearchParams(location.search).get(k); }
  function day(iso) { return iso ? String(iso).slice(0, 10) : "-"; }
  function when(iso) { return iso ? String(iso).replace("T", " ").replace("Z", " UTC") : "-"; }
  function ago(iso) {
    var t = Date.parse(iso); if (isNaN(t)) return "";
    var s = Math.max(0, (Date.now() - t) / 1000);
    if (s < 90) return "just now";
    if (s < 5400) return Math.round(s / 60) + " minutes ago";
    if (s < 129600) { var h = Math.round(s / 3600); return h + (h === 1 ? " hour ago" : " hours ago"); }
    var d = Math.round(s / 86400); return d + (d === 1 ? " day ago" : " days ago");
  }
  function bytes(n) {
    if (n == null) return "-";
    var u = ["bytes", "KB", "MB", "GB", "TB"], i = 0, v = Number(n);
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return (i ? v.toFixed(1) : v) + " " + u[i];
  }
  function plural(n, one, many) { return n + " " + (n === 1 ? one : many); }
  function panel(title, body, cls, right) {
    return '<section class="ch ' + (cls || "") + '"><div class="ch-head"><span>' + esc(title) + "</span>" +
      (right ? '<span class="ch-r">' + right + "</span>" : "") + '</div><div class="ch-body">' + body + "</div></section>";
  }
  function unb64(s) {
    var bin = atob(String(s || "")), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function hex(buf) {
    var b = new Uint8Array(buf), s = "";
    for (var i = 0; i < b.length; i++) s += (b[i] < 16 ? "0" : "") + b[i].toString(16);
    return s;
  }
  async function getJSON(url) {
    var r = await fetch(url, { headers: { Accept: "application/json" }, credentials: "omit" });
    var body = null;
    try { body = await r.json(); } catch (e) { body = null; }
    if (!r.ok) throw new Error((body && body.detail) || ("Morrow answered " + r.status));
    return body;
  }

  /* ---------- the depth dial, shared with the instrument (morrow_depth, ?depth=) ---------- */
  var depth = DEPTHS.indexOf(param("depth")) >= 0 ? param("depth") : LS.get("morrow_depth", "standard");
  if (DEPTHS.indexOf(depth) < 0) depth = "standard";
  function dial() {
    var box = $("#i-dial");
    document.documentElement.setAttribute("data-depth", depth);
    box.innerHTML = DEPTHS.map(function (d) { return '<button type="button" data-d="' + d + '" aria-pressed="' + (d === depth) + '">' + d + "</button>"; }).join("");
    box.onclick = function (e) {
      var b = e.target.closest("button[data-d]"); if (!b) return;
      depth = b.getAttribute("data-d"); LS.set("morrow_depth", depth);
      var u = new URL(location.href);
      if (depth === "standard") u.searchParams.delete("depth"); else u.searchParams.set("depth", depth);
      history.replaceState(null, "", u.pathname + u.search + u.hash);
      dial();
      if (STATE.record) render();
    };
  }

  /* ---------- the same bytes and rules as the server ---------- */
  function statement(sig) {
    return enc.encode(["morrow-signature/1", "domain " + sig.domain, "key " + sig.key, "type " + sig.type,
      "name " + sig.name, "size " + String(sig.size), "sha512 " + sig.sha512, "signed-at " + sig.signed_at].join("\n") + "\n");
  }
  function manifestBytes(entries) {
    return enc.encode(["morrow-manifest/1"].concat(entries.map(function (e) { return e.sha512 + " " + String(e.size) + " " + e.path; })).join("\n") + "\n");
  }
  function cryptoCheck(sig, key) {
    var msg = statement(sig), ml = false, ed = false;
    try { ml = window.MorrowPQ.mlDsa65Verify(unb64(sig.ml_dsa_65), msg, unb64(key.ml_dsa_65), CTX); } catch (e) { ml = false; }
    try { ed = window.MorrowPQ.ed25519Verify(unb64(sig.ed25519), msg, unb64(key.ed25519)); } catch (e) { ed = false; }
    return [ml, ed];
  }
  function assess(sig, key, record, fileHash, fileSize) {
    var checks = [];
    function check(name, ok, detail) { checks.push({ check: name, ok: !!ok, detail: detail }); return !!ok; }
    function verdict(valid, reason) { return { valid: valid, reason: reason, checks: checks, record: record }; }
    if (fileHash != null) {
      var same = fileHash === sig.sha512 && (fileSize == null || fileSize === sig.size);
      if (!check("file", same, same ? "The file's SHA-512 and size match the signature." : "The file's SHA-512 or size differs from the signed one: this is not the file that was signed."))
        return verdict(false, "This file is not the one that was signed.");
    }
    if (!check("key", !!key, key ? "The key is on " + sig.domain + "'s public record." : sig.domain + " has no key " + sig.key + " on its public record."))
      return verdict(false, "The signing key is not registered for this domain.");
    var st = key.state || {};
    if (!check("domain", st.domain_verified, st.domain_verified ? "The key's owner still controls the domain (DNS verified)." : "The organization that registered this key no longer has the domain verified."))
      return verdict(false, "The key's owner no longer has this domain verified.");
    var r = cryptoCheck(sig, key);
    check("ml_dsa_65", r[0], r[0] ? "ML-DSA-65 (FIPS 204) signature verifies, checked in this browser." : "ML-DSA-65 signature does not verify.");
    check("ed25519", r[1], r[1] ? "Ed25519 signature verifies, checked in this browser." : "Ed25519 signature does not verify.");
    if (!(r[0] && r[1])) return verdict(false, "The signature does not verify: both ML-DSA-65 and Ed25519 must.");
    if (record && record.withdrawn) {
      check("withdrawn", false, "Withdrawn by the publisher on " + when(record.withdrawn.at) + ": " + record.withdrawn.note);
      return verdict(false, "The publisher withdrew this signature.");
    }
    if (st.status === "revoked") {
      var ok = !!record && String(record.recorded_at) < String(st.compromised_since);
      check("key_status", ok, ok ? "The key was revoked, but Morrow recorded this signature on " + when(record.recorded_at) + ", before the key stopped being trusted (" + when(st.compromised_since) + ")."
        : "The key was revoked: nothing it signed is trusted unless Morrow recorded it before " + when(st.compromised_since) + ".");
      return verdict(ok, ok ? "Valid: recorded before the key was revoked." : "The signing key was revoked.");
    }
    if (st.status === "retired") {
      var ok2 = String(sig.signed_at) <= String(st.retired_at);
      check("key_status", ok2, ok2 ? "Signed before the key was retired on " + when(st.retired_at) + "." : "Signed after the key was retired on " + when(st.retired_at) + ".");
      return verdict(ok2, ok2 ? "Valid: signed before the key was retired." : "Signed with a retired key.");
    }
    check("key_status", true, "The key is active.");
    return verdict(true, record ? "Valid post-quantum signature." : "Valid post-quantum signature. It is not on Morrow's public record.");
  }

  /* ---------- hashing, in this browser ---------- */
  var NATIVE_LIMIT = 512 * 1024 * 1024;
  async function sha512File(file, progress) {
    if (file.size <= NATIVE_LIMIT && window.crypto && crypto.subtle) {
      progress("Hashing " + file.name + " in this browser");
      return hex(await crypto.subtle.digest("SHA-512", await file.arrayBuffer()));
    }
    var h = window.MorrowPQ.sha512Create(), done = 0, step = 8 * 1024 * 1024;
    for (var off = 0; off < file.size; off += step) {
      var chunk = new Uint8Array(await file.slice(off, off + step).arrayBuffer());
      h.update(chunk); done += chunk.length;
      progress("Hashing " + file.name + " in this browser: " + Math.floor(done * 100 / file.size) + "%");
      await new Promise(function (res) { setTimeout(res, 0); });
    }
    return hex(h.digest());
  }

  /* ---------- state and rendering ---------- */
  var STATE = { domain: "", record: null, results: [] };
  function keyFor(sig) { return (STATE.record.keys || []).filter(function (k) { return k.key_id === sig.key && k.domain === sig.domain; })[0] || null; }
  function statusOf(k) { return k.state.domain_verified ? k.state.status : "unverified"; }

  function sentence(rec) {
    var c = rec.counts, keys = rec.keys || [];
    if (!keys.length) return rec.domain + " has no post-quantum signing keys on Morrow.";
    var parts = [rec.domain + " has " + plural(c.active_keys, "active post-quantum signing key", "active post-quantum signing keys")];
    if (depth !== "plain") parts.push(plural(c.this_month, "file", "files") + " signed this month");
    parts.push(c.last_recorded_at ? "the latest " + ago(c.last_recorded_at) : "no signature on the record yet");
    return parts.join("; ") + ".";
  }

  function keysPanel(rec) {
    var keys = rec.keys || [];
    if (!keys.length) return panel("Keys", '<p class="i-muted">No key is registered for ' + esc(rec.domain) + ". A signature that claims to be from " + esc(rec.domain) + " cannot be checked here.</p>");
    var rows = keys.map(function (k) {
      var s = statusOf(k), st = k.state;
      var note = s === "retired" ? "retired " + day(st.retired_at) + "; signatures dated before stay valid"
        : s === "revoked" ? "revoked " + day(st.revoked_at) + (st.revocation_note ? ": " + st.revocation_note : "") + ". Only signatures Morrow recorded before " + when(st.compromised_since) + " stay valid"
        : s === "unverified" ? "the owner no longer has " + rec.domain + " verified" : "signs for " + rec.domain;
      var hist = (k.events || []).map(function (e) { return "<li>" + esc(when(e.created_at)) + ": " + esc(e.event) + (e.note ? " (" + esc(e.note) + ")" : "") + "</li>"; }).join("");
      return "<tr><td><span class=\"v-status\" data-s=\"" + s + "\">" + esc(s) + "</span></td><td>" + esc(k.label || "") +
        '<div class="mono v-key i-fine">' + esc(k.key_id) + "</div>" +
        '<div class="v-expert"><div class="i-fine">ML-DSA-65 public key (1952 bytes)</div><div class="v-pk">' + esc(k.ml_dsa_65) + '</div><div class="i-fine">Ed25519 public key</div><div class="v-pk">' + esc(k.ed25519) + "</div></div>" +
        '</td><td class="v-standard mono">' + esc(day(k.registered_at)) + "</td><td>" + esc(note) +
        (hist ? '<ul class="v-hist v-standard">' + hist + "</ul>" : "") + "</td></tr>";
    }).join("");
    return panel("Keys", '<div class="i-table-wrap"><table class="i-table"><thead><tr><th>Status</th><th>Key</th><th class="v-standard">Registered</th><th>Meaning</th></tr></thead><tbody>' + rows + "</tbody></table></div>",
      "", plural(rec.counts.active_keys, "active", "active"));
  }

  function sigsPanel(rec) {
    var sigs = rec.signatures || [];
    if (!sigs.length) return panel("Signatures on the record", '<p class="i-muted">Nothing has been put on the public record yet. Signature files made with morrow-sign can still be checked above.</p>');
    var shown = depth === "plain" ? sigs.slice(0, 5) : sigs;
    var rows = shown.map(function (s) {
      var k = keyFor(s), w = s.withdrawn;
      var status = w ? "withdrawn" : k ? statusOf(k) : "unverified";
      return "<tr><td>" + esc(s.name) + (s.type === "manifest" ? ' <span class="i-fine">site manifest, ' + plural(s.entry_count, "file", "files") + "</span>" : "") +
        (w ? '<div class="i-fine">Withdrawn ' + esc(day(w.at)) + ": " + esc(w.note) + "</div>" : "") +
        '<div class="v-expert mono i-fine v-key">sha512 ' + esc(s.sha512) + "</div></td>" +
        '<td class="v-standard num">' + esc(bytes(s.size)) + '</td><td class="mono">' + esc(day(s.recorded_at)) + "</td>" +
        '<td class="v-standard mono i-fine">' + esc(s.key) + "</td><td>" + (w ? '<span class="v-status" data-s="withdrawn">withdrawn</span>' : '<span class="v-status" data-s="' + status + '">key ' + esc(status) + "</span>") + "</td></tr>";
    }).join("");
    return panel("Signatures on the record", '<div class="i-table-wrap"><table class="i-table"><thead><tr><th>File</th><th class="v-standard">Size</th><th>Recorded</th><th class="v-standard">Key</th><th>State</th></tr></thead><tbody>' + rows + "</tbody></table></div>" +
      (shown.length < sigs.length ? '<p class="i-fine">' + (sigs.length - shown.length) + " more at standard depth.</p>" : ""),
      "", plural(rec.counts.total, "on record", "on record"));
  }

  function dropPanel() {
    var wanted = param("sha512"), wantedName = param("file");
    var intro = wanted ? "<p>You followed a link for " + (wantedName ? "<b>" + esc(wantedName) + "</b>" : "one file") + ". Drop that file here to check it.</p>" : "";
    return panel("Check a file", intro +
      '<label class="v-drop" id="drop"><input type="file" id="pick" multiple><b>Drop a file here, or choose one</b>' +
      '<span class="i-muted">Add its .morrow-sig file too if you have it. The file stays in this browser.</span></label>' +
      '<p class="i-fine v-standard">The file is hashed here (SHA-512) and the signature is checked here with ML-DSA-65 (FIPS 204) and Ed25519; a signature counts only when both verify. ' +
      "If the file is not among the latest signatures, this page asks Morrow for signatures with that SHA-512: the fingerprint is sent, never the file.</p>" +
      '<p class="i-fine v-expert">On your own machine: <code>morrow-sign verify FILE --domain ' + esc(STATE.domain) + "</code>. As JSON: <code>GET /api/verify/" + esc(STATE.domain) + "</code>, <code>POST /api/verify</code>.</p>" +
      '<div class="v-results" id="results" aria-live="polite">' + STATE.results.map(resultHtml).join("") + "</div>", "", "nothing is uploaded");
  }

  function resultHtml(r) {
    if (r.pending) return '<div class="v-result"><div class="v-head"><span class="v-verdict">' + esc(r.pending) + "</span></div></div>";
    var checks = (r.checks || []).map(function (c) { return '<li data-ok="' + c.ok + '">' + esc(c.detail) + "</li>"; }).join("");
    return '<div class="v-result" data-ok="' + r.valid + '"><div class="v-head"><span class="v-verdict">' + (r.valid ? "VALID" : "NOT VALID") + "</span><b>" + esc(r.file) + "</b>" +
      '<span class="i-muted">' + esc(r.reason) + "</span></div>" +
      (r.via ? '<p class="i-fine">' + esc(r.via) + "</p>" : "") +
      '<ul class="v-checks' + (depth === "plain" ? " v-standard" : "") + '">' + checks + "</ul>" +
      (r.sha512 ? '<p class="i-fine mono v-expert v-key">sha512 ' + esc(r.sha512) + "</p>" : "") + "</div>";
  }

  function render() {
    var rec = STATE.record;
    $("#say").textContent = sentence(rec);
    document.title = "Verify " + rec.domain + " - Morrow";
    $("#main").innerHTML = dropPanel() + keysPanel(rec) + sigsPanel(rec) +
      panel("How this check works", "<p>" + esc(rec.domain) + " signs its files on its own machines with morrow-sign. Morrow never sees the private keys. " +
        "Each signature is made twice, with ML-DSA-65, a post-quantum algorithm standardised by NIST in FIPS 204, and with Ed25519, a classical algorithm; " +
        "this page accepts a signature only when both verify, so it stays trustworthy unless both are broken.</p>" +
        '<p class="v-standard">Morrow accepted these keys only after ' + esc(rec.domain) + " proved it controls the domain with a DNS record, and lists every key's history: when it was registered, retired or revoked.</p>", "v-standard");
    wireDrop();
  }

  function paintResults() { var box = $("#results"); if (box) box.innerHTML = STATE.results.map(resultHtml).join(""); }

  function wireDrop() {
    var drop = $("#drop"), pick = $("#pick");
    if (!drop) return;
    ["dragenter", "dragover"].forEach(function (t) { drop.addEventListener(t, function (e) { e.preventDefault(); drop.classList.add("over"); }); });
    ["dragleave", "drop"].forEach(function (t) { drop.addEventListener(t, function (e) { e.preventDefault(); drop.classList.remove("over"); }); });
    drop.addEventListener("drop", function (e) { handle(Array.prototype.slice.call(e.dataTransfer.files || [])); });
    pick.addEventListener("change", function () { handle(Array.prototype.slice.call(pick.files || [])); pick.value = ""; });
  }

  async function readSig(file) {
    if (file.size > 64 * 1024) throw new Error(file.name + " is too large to be a signature file.");
    var doc = JSON.parse(await file.text());
    if (!doc || doc.format !== "morrow-signature/1") throw new Error(file.name + " is not a Morrow signature file.");
    return doc;
  }

  async function handle(files) {
    if (!files.length) return;
    if (!window.MorrowPQ) { STATE.results = [{ file: "", valid: false, reason: "The verifier did not load. Reload the page.", checks: [] }]; paintResults(); return; }
    var sigs = [], data = [];
    for (var i = 0; i < files.length; i++) {
      if (/\.morrow-sig$/i.test(files[i].name)) {
        try { sigs.push({ name: files[i].name, doc: await readSig(files[i]) }); } catch (e) { STATE.results.unshift({ file: files[i].name, valid: false, reason: e.message, checks: [] }); }
      } else data.push(files[i]);
    }
    for (var j = 0; j < data.length; j++) {
      var f = data[j], slot = { pending: "Hashing " + f.name };
      STATE.results.unshift(slot); paintResults();
      var result;
      try {
        var digest = await sha512File(f, function (msg) { slot.pending = msg; paintResults(); });
        slot.pending = "Checking the signature in this browser"; paintResults();
        result = await checkFile(f, digest, sigs);
      } catch (e) {
        result = { valid: false, reason: e.message || String(e), checks: [] };
      }
      result.file = f.name;
      STATE.results[STATE.results.indexOf(slot)] = result;
      paintResults();
    }
    if (!data.length && sigs.length) {
      STATE.results.unshift({ file: sigs[0].name, valid: false, reason: "Add the file this signature is for: the check needs both.", checks: [] });
      paintResults();
    }
  }

  function recordFor(doc) {
    return (STATE.record.signatures || []).filter(function (s) { return s.ml_dsa_65 === doc.ml_dsa_65 && s.ed25519 === doc.ed25519; })[0] || null;
  }

  async function lookup(digest) {
    return getJSON("/api/verify/" + encodeURIComponent(STATE.domain) + "/lookup?sha512=" + digest);
  }

  async function checkFile(file, digest, sigs) {
    var mine = sigs.filter(function (s) { return s.name.toLowerCase() === (file.name + ".morrow-sig").toLowerCase() || s.doc.sha512 === digest; });
    if (mine.length) {
      var doc = mine[0].doc;
      if (doc.domain !== STATE.domain) return { valid: false, reason: "This signature claims to be from " + doc.domain + ", not " + STATE.domain + ". Check it at /verify/" + doc.domain + ".", checks: [] };
      var rec = recordFor(doc);
      if (!rec) {
        var found = await lookup(doc.sha512);
        rec = (found.signatures || []).filter(function (s) { return s.ml_dsa_65 === doc.ml_dsa_65 && s.ed25519 === doc.ed25519; })[0] || null;
      }
      var r = assess(doc, keyFor(doc), rec, digest, file.size);
      r.via = "Checked against " + mine[0].name + (rec ? ", which is on the public record (recorded " + when(rec.recorded_at) + ")." : ".");
      r.sha512 = digest;
      return r;
    }
    var direct = (STATE.record.signatures || []).filter(function (s) { return s.sha512 === digest && s.type === "file"; });
    var listed = [];
    if (!direct.length) {
      var res = await lookup(digest);
      direct = res.signatures || [];
      listed = res.in_manifests || [];
    }
    var best = null;
    for (var i = 0; i < direct.length; i++) {
      var r1 = assess(direct[i].document, keyFor(direct[i].document), direct[i], digest, file.size);
      r1.via = "Found on " + STATE.domain + "'s public record, recorded " + when(direct[i].recorded_at) + ".";
      r1.sha512 = digest;
      if (r1.valid) return r1;
      best = best || r1;
    }
    for (var m = 0; m < listed.length; m++) {
      var full = await getJSON("/api/verify/" + encodeURIComponent(STATE.domain) + "/signatures/" + encodeURIComponent(listed[m].id));
      var mbytes = manifestBytes(full.entries || []);
      var mhash = hex(await crypto.subtle.digest("SHA-512", mbytes));
      var entry = (full.entries || []).filter(function (e) { return e.sha512 === digest && e.size === file.size; })[0];
      var r2 = assess(full.document, keyFor(full.document), full, mhash, mbytes.length);
      r2.checks.unshift({ check: "listed", ok: !!entry, detail: entry ? "Listed in the signed site manifest as " + entry.path + "." : "Not in the signed site manifest." });
      if (!entry) { r2.valid = false; r2.reason = "The file is not in the signed manifest."; }
      r2.via = "Found in " + full.name + " (" + plural((full.entries || []).length, "file", "files") + "), rebuilt and hashed in this browser.";
      r2.sha512 = digest;
      if (r2.valid) return r2;
      best = best || r2;
    }
    return best || { valid: false, reason: STATE.domain + " has no signature on record for this file. If you have its .morrow-sig file, drop both together.", checks: [], sha512: digest };
  }

  /* ---------- the domain form, when no domain is in the address ---------- */
  function home() {
    $("#say").textContent = "Check a file against its publisher's post-quantum signature.";
    $("#main").innerHTML = panel("Whose file is it?", '<form class="v-form" id="vf"><label class="i-field"><span class="p">&rsaquo;</span>' +
      '<input id="vd" name="d" placeholder="the publisher\'s domain, like example.com" autocomplete="off" spellcheck="false" aria-label="Publisher domain"></label>' +
      '<p class="i-fine">Morrow lists the keys a domain registered and the signatures it published. Your file is checked in this browser and never uploaded.</p></form>');
    $("#vf").addEventListener("submit", function (e) {
      e.preventDefault();
      var d = $("#vd").value.trim().toLowerCase().replace(/^[a-z][a-z0-9+.-]*:\/\//, "").split(/[/?#]/)[0];
      if (d) location.href = "/verify/" + encodeURIComponent(d);
    });
  }

  async function boot() {
    dial();
    var segs = location.pathname.split("/").filter(Boolean);
    if (segs.length < 2) return home();
    STATE.domain = decodeURIComponent(segs[1]).toLowerCase();
    try {
      STATE.record = await getJSON("/api/verify/" + encodeURIComponent(STATE.domain) + "?limit=100");
      STATE.domain = STATE.record.domain;
      render();
    } catch (e) {
      $("#say").textContent = e.message || "Morrow could not load this domain's record.";
      $("#main").innerHTML = "";
    }
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot); else boot();
})();
