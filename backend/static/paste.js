/*
 * Paste anything: the home input also reads a certificate, a server or SSH configuration, a CBOM, a
 * repository link or a traffic capture (instrument.js calls in here; services/paste_anything.py answers).
 *
 *   MorrowPaste.attach({ form, input, hint, out })   wire the file picker, drop zone and paste
 *   MorrowPaste.wants(text)                          true when the server should read the text
 *   MorrowPaste.read(text)                           send it and show the answer in `out`
 *
 * A domain never comes here: instrument.js opens /r/<domain> itself, as before. A private key never
 * leaves the browser: it is recognised here, the field is cleared and the warning shown, without a
 * request (the server refuses one too). Same origin only; no inline script or style; nothing moves
 * on its own.
 */
(function () {
  "use strict";
  function I() { return window.MorrowIns; }
  function esc(v) { return I().esc(v); }

  var MAX_BYTES = 10 * 1024 * 1024;
  var PRIVATE = /-----BEGIN (?:[A-Z0-9]+ ){0,4}PRIVATE KEY(?: BLOCK)?-----|PuTTY-User-Key-File-|"kty"\s*:[^}]*"d"\s*:/;
  var KEYSTORE = /\.(p12|pfx|jks|jceks|keystore|bcfks|ppk|pvk|snk)$/i;
  var REPO = /^(?:https?:\/\/)?(?:www\.)?(?:github\.com|gitlab\.com|bitbucket\.org)\/[^\s\/]+\/[^\s\/]+|^git@(?:github\.com|gitlab\.com|bitbucket\.org):/i;
  var W = { form: null, input: null, hint: null, out: null, last: null, busy: false };
  var KEY_WARNING = "This contains a private key. Morrow did not send it anywhere and has cleared it from the box. Treat the key as exposed: anything pasted into a web page may have passed through your clipboard, browser extensions or a proxy. Replace it (a new key and certificate, or a new SSH host key) and revoke the old certificate. Paste the certificate (the BEGIN CERTIFICATE block) instead.";

  function wants(text) {
    var t = String(text || "").trim();
    if (!t) return false;
    return /\n/.test(t) || t.length > 200 || REPO.test(t) || /-----BEGIN/.test(t) || /^[\[{<]/.test(t) || PRIVATE.test(t) ||
      /^(?:KexAlgorithms|Ciphers|MACs|ssl_|SSL[A-Z]|ssl-default|Enable-Tls|Disable-Tls|jdk\.tls\.|MinProtocol|Groups\s*=)/.test(t);
  }

  function setHint(text, tone) {
    if (!W.hint) return;
    if (tone) W.hint.setAttribute("data-tone", tone); else W.hint.removeAttribute("data-tone");
    W.hint.textContent = text;
  }

  function refuseKey() {
    W.input.value = ""; grow();
    W.last = null;
    show({ kind: "private_key", what: "A private key. Morrow did not read it.", headline: KEY_WARNING, tone: "bad", refused: true,
      privacy: "Nothing was sent: the key was recognised in this page and cleared.", next: [] });
  }

  function b64(buf) {
    var bytes = new Uint8Array(buf), out = "", step = 0x8000;
    for (var i = 0; i < bytes.length; i += step) out += String.fromCharCode.apply(null, bytes.subarray(i, i + step));
    return btoa(out);
  }

  function post(body) {
    return fetch("/api/public/paste", { method: "POST", credentials: "omit", cache: "no-store",
      headers: { Accept: "application/json", "Content-Type": "application/json" }, body: JSON.stringify(body) })
      .then(function (r) {
        return r.text().then(function (t) {
          var b = null; try { b = t ? JSON.parse(t) : null; } catch (e) { b = null; }
          if (r.status === 422 && b && b.kind === "private_key") return b;
          if (!r.ok) { var err = new Error((b && b.detail) || ("The server answered " + r.status + ".")); err.retryAfter = +(r.headers.get("Retry-After") || 0); throw err; }
          return b;
        });
      });
  }

  function send(body) {
    if (W.busy) return;
    W.busy = true; W.last = body;
    var go = W.form && W.form.querySelector(".i-safe-go");
    if (go) go.setAttribute("aria-busy", "true");
    setHint("Reading it on the server, in memory only…");
    post(body).then(function (res) {
      if (res && res.kind === "private_key") { W.input.value = ""; grow(); W.last = null; }
      if (res && res.redirect && res.kind === "domain") { location.href = res.redirect; return; }
      setHint("");
      show(res);
    }).catch(function (e) {
      setHint(e.message + (e.retryAfter ? " Try again in " + e.retryAfter + " s." : ""), "bad");
    }).then(function () { W.busy = false; if (go) go.removeAttribute("aria-busy"); });
  }

  function read(text) {
    if (PRIVATE.test(text)) { refuseKey(); return; }
    send({ content: String(text), encoding: "text" });
  }

  function readFile(file) {
    if (!file) return;
    if (KEYSTORE.test(file.name || "")) { refuseKey(); return; }
    if (file.size > MAX_BYTES) { setHint("That file is larger than 10 MB, the most Morrow reads.", "bad"); return; }
    var fr = new FileReader();
    fr.onload = function () {
      var buf = fr.result, head = "";
      try { head = new TextDecoder("utf-8", { fatal: false }).decode(new Uint8Array(buf, 0, Math.min(buf.byteLength, 1048576))); } catch (e) { head = ""; }
      if (PRIVATE.test(head)) { refuseKey(); return; }
      W.input.value = ""; grow();
      setHint("Read " + file.name + " (" + Math.max(1, Math.round(file.size / 1024)) + " KB).");
      send({ content: b64(buf), encoding: "base64", name: String(file.name || "").slice(0, 120) });
    };
    fr.onerror = function () { setHint("That file could not be opened.", "bad"); };
    fr.readAsArrayBuffer(file);
  }

  /* ── the answer ──────────────────────────────────────────────────────── */
  var KIND = { certificate: "Certificate", config: "Configuration file", cbom: "CBOM", repository: "Repository",
    capture: "Traffic capture", private_key: "Private key", unknown: "Not recognised", ambiguous: "Which kind?", domain_list: "Domains", domain: "Domain" };

  function list(items, cls) {
    return items && items.length ? '<ul class="pa-list' + (cls ? " " + cls : "") + '">' + items.map(function (x) { return "<li>" + esc(x) + "</li>"; }).join("") + "</ul>" : "";
  }
  function dl(rows) {
    rows = rows.filter(function (r) { return r[1] != null && r[1] !== "" && !(Array.isArray(r[1]) && !r[1].length); });
    if (!rows.length) return "";
    return '<dl class="pa-dl">' + rows.map(function (r) { return "<dt>" + esc(r[0]) + "</dt><dd>" + esc(Array.isArray(r[1]) ? r[1].join(", ") : r[1]) + "</dd>"; }).join("") + "</dl>";
  }
  function table(head, rows) {
    return '<div class="i-table-wrap"><table class="i-table pa-table"><thead><tr>' + head.map(function (h) { return '<th scope="col">' + esc(h) + "</th>"; }).join("") +
      "</tr></thead><tbody>" + rows.map(function (r) { return "<tr>" + r.map(function (c, i) { return i === 0 && c && c.tone ? '<td><span class="pa-tone" data-tone="' + esc(c.tone) + '">' + esc(c.text) + "</span></td>" : "<td>" + esc(c) + "</td>"; }).join("") + "</tr>"; }).join("") + "</tbody></table></div>";
  }

  function body(res) {
    var d = res.details || {}, out = "";
    if (res.kind === "certificate") {
      (d.items || []).forEach(function (c, i) {
        out += '<div class="pa-item" data-tone="' + esc(c.tone) + '"><p class="pa-item-h"><b>' + esc(c.role === "request" ? "Signing request" : c.role === "public_key" ? "Public key" : (i === 0 ? "Certificate" : "Issuer " + i)) + "</b> " + esc(c.subject || "") + "</p>" +
          dl([["Key", c.key], ["Signature", c.signature_algorithm], ["Valid", c.not_before ? c.not_before + " to " + c.not_after + (c.expired ? " (expired)" : " (" + c.days_left + " days left)") : ""],
            ["Issuer", c.self_signed ? "self-signed" : c.issuer], ["Names", c.dns_names && c.dns_names.length ? c.dns_names.join(", ") + (c.dns_names_total > c.dns_names.length ? " and " + (c.dns_names_total - c.dns_names.length) + " more" : "") : ""],
            ["Quantum", c.verdict]]) + "</div>";
      });
    } else if (res.kind === "config") {
      out += dl([["Hybrid post-quantum", { on: "on", off: "off", "default": "not set: the software's default decides" }[res.hybrid_pq]],
        ["Protocols", d.protocols || (d.key_exchange === undefined ? "not set" : null)], ["Key exchange", d.groups || d.key_exchange || "not set"],
        ["Ciphers", d.ciphers ? d.ciphers.slice(0, 12).join(", ") + (d.ciphers.length > 12 ? " …" : "") : null], ["TLS 1.3 suites", d.tls13_suites],
        ["MACs", d.macs], ["Host key algorithms", d.host_key_algorithms]]);
      if ((d.settings || []).length && I().depth() !== "plain") {
        out += '<details class="ms-more"><summary>The ' + d.settings.length + " line" + (d.settings.length > 1 ? "s" : "") + " Morrow read</summary>" +
          table(["Line", "Setting", "Value"], d.settings.map(function (s) { return [String(s.line), s.setting, s.value]; })) + "</details>";
      }
    } else if (res.kind === "cbom") {
      var r = d.by_risk || {};
      out += '<dl class="readouts">' + ["critical", "high", "medium", "low", "unknown"].map(function (k) { return I().reading(k[0].toUpperCase() + k.slice(1), String(r[k] || 0), k === "low" ? "v-ok" : ""); }).join("") + "</dl>";
      out += dl([["Components", d.components], ["Cryptographic assets", d.assets], ["Quantum-vulnerable", d.quantum_vulnerable], ["Post-quantum", d.post_quantum]]);
      if ((d.items || []).length) out += '<details class="ms-more"><summary>Every asset, worst first</summary>' +
        table(["Risk", "Asset", "Type", "Algorithm", "Seen"], d.items.map(function (a) { return [{ tone: a.risk === "low" ? "ok" : a.risk === "unknown" ? "warn" : "bad", text: a.risk }, a.name, a.type, a.algorithm || "-", String(a.occurrences || 0)]; })) + "</details>";
    } else if (res.kind === "capture") {
      out += '<dl class="readouts">' + I().reading("TLS connections", String(d.tls_connections || 0)) + I().reading("Post-quantum", String(d.post_quantum || 0), "v-ok") +
        I().reading("Classical", String(d.classical || 0)) + I().reading("Packets read", String(d.packets || 0)) + "</dl>";
      if ((d.connections || []).length) out += table(["Key exchange", "Server", "Name (SNI)", "Client offered"], d.connections.map(function (c) {
        return [{ tone: c.post_quantum ? "ok" : c.negotiated_group ? "bad" : "warn", text: c.negotiated_group || "not visible" }, c.server, c.sni || "-", (c.offered_groups || []).slice(0, 6).join(", ") || "-"];
      }));
    } else if (res.kind === "ambiguous") {
      out += '<div class="ms-row">' + (res.choices || []).map(function (c) { return '<button type="button" class="i-btn" data-as="' + esc(c.as) + '">' + esc(c.label) + "</button>"; }).join("") + "</div>";
    } else if (res.kind === "domain_list") {
      out += "<p>" + esc((d.domains || []).join(", ")) + (d.count > (d.domains || []).length ? " …" : "") + "</p>";
    }
    return out;
  }

  function show(res) {
    if (!W.out) return;
    res = res || {};
    var tone = res.tone || "warn";
    var nxt = (res.next || []).map(function (n) {
      var href = String(n.href || "");
      var ext = /^https:\/\//.test(href);
      return '<a class="i-btn' + (n.primary ? " solid" : "") + '" href="' + esc(href) + '"' + (ext ? ' rel="noopener" target="_blank"' : "") + ">" + esc(n.label) + "</a>";
    }).join("");
    var recipe = res.recipe && window.MorrowSafe && window.MorrowSafe.recipe
      ? I().panel("", "Make it safe: " + res.recipe.name, window.MorrowSafe.recipe(res.recipe), { ch: "tools", id: "paste-recipe" }) : "";
    var harvest = (res.harvest || []).length ? I().panel("", "Harvest clock", list(res.harvest), { ch: "grade" }) : "";
    var findings = (res.findings || []).length ? '<h3 class="pa-h">What else Morrow saw</h3>' + list(res.findings) : "";
    W.out.innerHTML = '<section class="ch pa-out" data-ch="tools" data-tone="' + esc(tone) + '" aria-labelledby="pa-what"><div class="ch-head"><span>' + esc(KIND[res.kind] || "Result") + '</span><span class="ch-r">' +
      (res.refused ? "refused" : "not stored") + '</span></div><div class="ch-body">' +
      '<p class="pa-what" id="pa-what" tabindex="-1">' + esc(res.what || "") + "</p>" +
      '<p class="pa-head" data-tone="' + esc(tone) + '">' + esc(res.headline || "") + "</p>" + body(res) + findings + list(res.notes, "pa-notes") +
      (nxt ? '<div class="ms-row pa-next">' + nxt + "</div>" : "") +
      '<p class="i-fine pa-privacy">' + esc(res.privacy || "") + "</p></div></section>" + harvest + recipe;
    var what = W.out.querySelector("#pa-what");
    if (what) what.focus({ preventScroll: false });
    I().say(res.what || "");
    W.out.querySelectorAll("[data-as]").forEach(function (b) {
      b.addEventListener("click", function () { if (W.last) send(Object.assign({}, W.last, { as: b.getAttribute("data-as") })); });
    });
    W.out.querySelectorAll('a[href="#paste-recipe"]').forEach(function (a) {
      a.addEventListener("click", function (e) { var t = W.out.querySelector("#paste-recipe"); if (t) { e.preventDefault(); t.scrollIntoView({ block: "start" }); var pre = t.querySelector("pre"); if (pre) pre.focus(); } });
    });
    W.out.querySelectorAll('a[href="/#paste"]').forEach(function (a) {
      a.addEventListener("click", function (e) { e.preventDefault(); W.input.focus(); W.input.select(); });
    });
    var c = W.out.querySelector("#ms-copy");
    if (c && res.recipe) c.addEventListener("click", function () { I().copy(res.recipe.snippet, c); });
  }

  /* ── the field ───────────────────────────────────────────────────────── */
  function grow() {
    var el = W.input; if (!el) return;
    var lines = (el.value.match(/\n/g) || []).length + 1;
    el.rows = Math.min(10, Math.max(1, lines));
    el.classList.toggle("pa-multi", lines > 1);
  }

  function attach(o) {
    W.form = o.form; W.input = o.input; W.hint = o.hint; W.out = o.out;
    var el = W.input, form = W.form;
    el.addEventListener("keydown", function (e) {
      if (e.key === "Enter" && !e.shiftKey && !e.isComposing) { e.preventDefault(); if (form.requestSubmit) form.requestSubmit(); else form.dispatchEvent(new Event("submit", { cancelable: true })); }
    });
    el.addEventListener("input", grow);
    el.addEventListener("paste", function () {
      setTimeout(function () {
        grow();
        var t = el.value;
        if (PRIVATE.test(t)) { refuseKey(); return; }
        if (/\n/.test(t.trim()) && wants(t)) read(t);   // a pasted file is read at once; a typed line waits for Enter
      }, 0);
    });
    var file = form.querySelector("#home-file"), pick = form.querySelector("#home-pick");
    if (pick && file) {
      pick.addEventListener("click", function () { file.click(); });
      file.addEventListener("change", function () { readFile(file.files && file.files[0]); file.value = ""; });
    }
    ["dragenter", "dragover"].forEach(function (t) {
      form.addEventListener(t, function (e) { if (e.dataTransfer && Array.prototype.indexOf.call(e.dataTransfer.types || [], "Files") >= 0) { e.preventDefault(); form.classList.add("pa-drop"); } });
    });
    ["dragleave", "dragend"].forEach(function (t) { form.addEventListener(t, function (e) { if (!form.contains(e.relatedTarget)) form.classList.remove("pa-drop"); }); });
    form.addEventListener("drop", function (e) {
      form.classList.remove("pa-drop");
      var f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
      if (f) { e.preventDefault(); readFile(f); }
    });
  }

  window.MorrowPaste = { attach: attach, wants: wants, read: read };
})();
