/* Morrow instrument: the public, no-account part of Morrow.
 *
 * One page (instrument.html) serves every view; the server sends it for "/", "/<domain>",
 * "/league", "/atlas", "/algorithms[/<id>]" and "/trust". The address is the interface: every
 * view's state lives in its URL (path plus query), so any view is a link someone else can open.
 *
 * Rules this file keeps:
 *   - Live data only. A number on screen came from an API response in this page load, or it is
 *     not shown. Nothing is sampled, faked or animated in.
 *   - Motion only when something real happens (a result arrives, a grade changes).
 *   - Only this origin is contacted. The tests check this file for other origins in fetch calls.
 *   - The technicality dial (plain / standard / expert) changes wording and depth on every view.
 */
(function () {
  "use strict";

  /* ── small helpers ─────────────────────────────────────────────────────── */
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
  function esc(v) {
    return String(v == null ? "" : v).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function enc(v) { return encodeURIComponent(v); }
  function num(n) { return n == null || isNaN(n) ? "-" : Number(n).toLocaleString("en-GB"); }
  function pct(x) { return x == null || isNaN(x) ? "-" : (Math.round(x * 1000) / 10) + "%"; }
  function day(iso) { if (!iso) return "-"; var d = new Date(iso); return isNaN(d) ? String(iso) : d.toISOString().slice(0, 10); }
  function stamp(iso) { if (!iso) return "-"; var d = new Date(iso); return isNaN(d) ? String(iso) : d.toISOString().slice(0, 16).replace("T", " ") + " UTC"; }
  function ago(iso) {
    var t = Date.parse(iso); if (isNaN(t)) return "";
    var s = Math.max(0, (Date.now() - t) / 1000);
    if (s < 90) return "just now";
    if (s < 5400) return Math.round(s / 60) + " min ago";
    if (s < 129600) return Math.round(s / 3600) + " h ago";
    return Math.round(s / 86400) + " days ago";
  }
  var LS = {
    get: function (k, d) { try { var v = localStorage.getItem(k); return v == null ? d : v; } catch (e) { return d; } },
    set: function (k, v) { try { localStorage.setItem(k, v); } catch (e) { /* private mode */ } }
  };

  function getJSON(url, opts) {
    opts = opts || {};
    var ctl = new AbortController();
    var timer = setTimeout(function () { ctl.abort(); }, opts.timeout || 45000);
    var headers = { Accept: "application/json" };
    if (opts.auth) headers.Authorization = "Bearer " + opts.auth;
    return fetch(url, { headers: headers, credentials: "same-origin", cache: opts.cache || "default", signal: ctl.signal })
      .then(function (r) {
        return r.text().then(function (t) {
          var body = null;
          try { body = t ? JSON.parse(t) : null; } catch (e) { body = null; }
          if (!r.ok) {
            var err = new Error((body && (body.detail || body.error)) || ("HTTP " + r.status));
            err.status = r.status; err.body = body; err.retryAfter = r.headers.get("Retry-After");
            throw err;
          }
          return body;
        });
      })
      .finally(function () { clearTimeout(timer); });
  }
  function sha256Hex(buf) {
    return crypto.subtle.digest("SHA-256", buf).then(function (h) {
      return Array.prototype.map.call(new Uint8Array(h), function (b) { return b.toString(16).padStart(2, "0"); }).join("");
    });
  }
  /* Canonical JSON as services/proof_signing.canonical_bytes writes it: sorted keys, no spaces. */
  function canonical(v) {
    if (v === null || typeof v !== "object") return JSON.stringify(v);
    if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
    return "{" + Object.keys(v).sort().map(function (k) { return JSON.stringify(k) + ":" + canonical(v[k]); }).join(",") + "}";
  }
  function copy(text, btn) {
    var done = function () { if (btn) { var o = btn.textContent; btn.textContent = "Copied"; setTimeout(function () { btn.textContent = o; }, 1400); } };
    if (navigator.clipboard) navigator.clipboard.writeText(text).then(done, function () {});
  }

  /* ── state that lives in the URL ───────────────────────────────────────── */
  var url = new URL(location.href);
  function param(k) { return url.searchParams.get(k); }
  function setParam(k, v, push) {
    if (v == null || v === "") url.searchParams.delete(k); else url.searchParams.set(k, v);
    history[push ? "pushState" : "replaceState"](null, "", url.pathname + (url.search ? url.search : "") + url.hash);
  }

  /* The technicality dial. From the URL first (a shared link carries its depth), then this device. */
  var DEPTHS = ["plain", "standard", "expert"];
  var depth = DEPTHS.indexOf(param("depth")) >= 0 ? param("depth") : LS.get("morrow_depth", "standard");
  if (DEPTHS.indexOf(depth) < 0) depth = "standard";
  function byDepth(o) { return o[depth] != null ? o[depth] : o.standard; }

  /* What this visitor looked at last, on this device only. Never sent anywhere. */
  function recent() { try { return JSON.parse(LS.get("morrow_recent", "[]")) || []; } catch (e) { return []; } }
  function remember(kind, id, label) {
    var list = recent().filter(function (r) { return !(r.kind === kind && r.id === id); });
    list.unshift({ kind: kind, id: id, label: label, at: new Date().toISOString() });
    LS.set("morrow_recent", JSON.stringify(list.slice(0, 8)));
  }
  var token = LS.get("morrow_token", "");

  /* ── the recognizer: one input, many meanings ──────────────────────────── */
  var DOMAIN_RE = /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/;
  function asDomain(raw) {
    var s = String(raw || "").trim().toLowerCase();
    s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, "").split(/[/?#]/)[0].replace(/:\d+$/, "").replace(/\.$/, "");
    if (s.indexOf("*.") === 0) s = s.slice(2);
    return DOMAIN_RE.test(s) ? s : null;
  }
  /* Places: everything Morrow can show, reached by typing, from Ctrl+K, or by a link inside an
     answer. There is no menu. The console's views are places too (opened at /ui/#<view>). */
  var PLACES = [
    { t: "Sector averages", h: "/league", k: "league sectors averages banks government health", g: "Public" },
    { t: "Algorithms, with their history", h: "/algorithms", k: "algorithms reference history timeline pqc", g: "Public" },
    { t: "What this server runs, and how to check it", h: "/trust", k: "trust commit verify deploy log csp tracking reproducible", g: "Public" },
    { t: "Plain version, no scripts", h: "/plain", k: "plain text accessible screen reader no javascript", g: "Public" },
    { t: "Your estate through time", h: "/estate", k: "estate history scans time progress map atlas my", g: "Yours", ws: true },
    { t: "Domains you watch, and what changed", h: "/watching", k: "watch watching alerts notifications push changes feed webhook", g: "Yours", ws: true },
    { t: "About the scanner: what connects to your server", h: "/about-scanner", k: "scanner user agent logs bot crawler opt out morrowpqcheck", g: "Public" }
  ];
  var CONSOLE_PLACES = [["overview", "Overview", "posture summary"], ["scans", "TLS Scanner", "run scans, diff against a baseline"],
    ["assets", "Asset Inventory", "owners, tags, collections"], ["cbom", "CBOM / SBOM", "CycloneDX bill of materials"],
    ["hndl", "HNDL Exposure", "harvest-now-decrypt-later queue"], ["qday", "Q-Day Forecast", "CRQC trajectory, milestones"],
    ["graph", "Blast Radius", "certificate blast radius, CA contagion"], ["canaries", "Canaries & QTISN", "canary tokens, threat intel"],
    ["data-control", "Data Control", "AI permissions, data boundary, receipts"], ["airlock", "Quantum Airlock", "privacy wall, trust passports"],
    ["gateway", "Website Gateway", "domain ownership, filtering"], ["remediation", "Remediation", "fix queue, playbooks, code generation"],
    ["scanners", "Deep Scanners", "SAST, secrets, dependencies, IaC"], ["operations", "Operations", "drift, SLA, schedules"],
    ["governance", "Governance", "policies, compliance evidence"], ["board", "Board & ROI", "board risk, ROI models"],
    ["vendors", "Third Party", "vendor assessments"], ["integrations", "Integrations", "GitHub, Slack, Jira, webhooks, CI"],
    ["knowledge", "Knowledge", "knowledge base, provider capabilities"], ["admin", "Administration", "users, organizations, audit"],
    ["api", "API Explorer", "every endpoint"], ["guide", "Guide & Tutorial", "what every screen does"],
    ["g-airlock", "Airlock Guide", "deploying the collector"], ["g-trust-passport", "Passport Guide", "sharing proof"], ["g-admin-page", "Administrator Guide", "running the platform"]];
  CONSOLE_PLACES.forEach(function (p) { PLACES.push({ t: p[1], h: "/ui/#" + p[0], k: p[0] + " " + p[2] + " console", g: "Console", hint: p[2] }); });

  /* The signed-in workspace, if this browser has one: the console's own token, same origin. */
  var wsP = null;
  function workspace() {
    if (!wsP) wsP = getJSON("/scans?limit=100", { auth: token, cache: "no-store" })
      .then(function (r) { return { scans: Array.isArray(r) ? r : (r && (r.scans || r.items)) || [] }; })
      .catch(function () { return null; });
    return wsP;
  }
  var WS = null, CONN = null;
  workspace().then(function (w) { WS = w; });

  function scanCommand(q) {
    var m = /^(?:scan|rescan)\s+(.+)$/i.exec(q);
    return m ? asDomain(m[1]) : null;
  }
  function recognize(raw, limit) {
    var q = String(raw || "").trim(); var out = [];
    limit = limit || 10;
    if (!q) {
      // Things, not pages: what this person looked at, and what they might do next.
      recent().forEach(function (r) {
        out.push({ kind: r.kind, t: r.label, h: r.kind === "domain" ? "/" + r.id : r.kind === "algorithm" ? "/algorithms/" + r.id : r.id, hint: "looked at " + ago(r.at) });
        if (r.kind === "domain" && WS) out.push({ kind: "command", t: "scan " + r.id, h: "#scan", run: function () { startScan(r.id); }, hint: "add it to your estate" });
      });
      if (WS && WS.scans.length) out.unshift({ kind: "estate", t: "Your estate through time", h: "/estate", hint: WS.scans.length + " scan" + (WS.scans.length === 1 ? "" : "s") });
      if (CONN && CONN.kex) out.push({ kind: "algorithm", t: CONN.kex + ": what your browser used just now", h: "/algorithms/" + (CONN.status === "pq" ? "x25519mlkem768" : "x25519"), hint: CONN.status === "pq" ? "post-quantum" : "classical" });
      if (!out.length) out.push({ kind: "hint", t: "Type a domain, for example your bank's", h: "#", hint: "or an algorithm, a CVE, a commit" + (WS ? ", or scan example.com" : "") });
      return out.slice(0, limit);
    }
    var cmd = scanCommand(q);
    if (cmd) {
      out.push(WS ? { kind: "command", t: "scan " + cmd, h: "#scan", run: function () { startScan(cmd); }, hint: "in your workspace" }
                  : { kind: "command", t: "Sign in to scan " + cmd + " in your workspace", h: "/ui/", hint: "or grade it publicly below" });
      out.push({ kind: "domain", t: "Grade " + cmd + " publicly", h: "/" + cmd, hint: "no account needed" });
      return out;
    }
    var ref = window.MORROW_REF;
    var algo = ref && ref.find(q);
    if (algo) out.push({ kind: "algorithm", t: algo.name, h: "/algorithms/" + algo.id, hint: algo.kind });
    var cve = /^cve-\d{4}-\d{4,}$/i.test(q) ? q.toUpperCase() : null;
    if (cve) out.push({ kind: "cve", t: cve + " in the NVD", h: "https://nvd.nist.gov/vuln/detail/" + cve, hint: "opens nvd.nist.gov", ext: true });
    var d = !algo && !cve ? asDomain(q) : null;
    if (d) {
      out.push({ kind: "domain", t: "Grade " + d, h: "/" + d, hint: "is its connection quantum-safe?" });
      if (WS) out.push({ kind: "command", t: "scan " + d, h: "#scan", run: function () { startScan(d); }, hint: "add it to your estate" });
    }
    var sha = !d && /^[0-9a-f]{7,40}$/i.test(q) && /\d/.test(q) ? q.toLowerCase() : null;
    if (sha) out.push({ kind: "commit", t: "Commit " + sha.slice(0, 12), h: "/trust?commit=" + sha, hint: "is it the one this server runs?" });
    var words = q.toLowerCase().split(/\s+/).filter(Boolean);
    var pool = PLACES.filter(function (p) { return !p.ws || WS; }).map(function (p) { return { kind: "place", t: p.t, h: p.h, hay: (p.t + " " + p.k + " " + p.g).toLowerCase(), hint: p.hint || p.g }; });
    if (ref) ref.algorithms.forEach(function (a) { pool.push({ kind: "algorithm", t: a.name, h: "/algorithms/" + a.id, hay: [a.name, a.kind, a.family].concat(a.aka).join(" ").toLowerCase(), hint: a.kind }); });
    pool.filter(function (p) { return words.every(function (w) { return p.hay.indexOf(w) >= 0; }); })
      .forEach(function (p) { if (!out.some(function (o) { return o.h === p.h; })) out.push(p); });
    return out.slice(0, limit);
  }
  /* Remediation states in plain words. The server's values (verified_closed, pr_created ...) never
     reach a suggestion row; an unknown one reads "status recorded" rather than leaking through. */
  var FIX_STATUS = { suggested: "Suggested", pending: "Waiting for approval", open: "Open", approved: "Approved",
    rejected: "Rejected", in_progress: "In progress", pr_created: "Change proposed in a pull request",
    merged: "Change merged, not yet verified", validated: "Change validated", verified: "Verified",
    verified_closed: "Fixed and verified", closed: "Closed" };
  function fixStatus(v) { return FIX_STATUS[String(v || "").toLowerCase()] || "Status recorded"; }
  /* Your own assets and remediations, searched live in your workspace as you type. */
  function searchMine(q) {
    if (!WS || q.length < 2 || scanCommand(q)) return Promise.resolve([]);
    return getJSON("/search?limit=8&q=" + enc(q), { auth: token, cache: "no-store" }).then(function (r) {
      return ((r && r.results) || []).filter(function (x) { return x.type === "asset" || x.type === "remediation"; }).slice(0, 6).map(function (x) {
        var d = x.data || {};
        return x.type === "asset"
          ? { kind: "asset", t: x.title, h: "/estate/asset/" + enc(x.title), hint: [d.algorithm, d.tls_version, d.risk_level ? d.risk_level + " risk" : ""].filter(Boolean).join(" \u00b7 ") }
          : { kind: "fix", t: x.title, h: "/ui/#remediation", hint: fixStatus(d.status) + (d.target_host ? " \u00b7 " + d.target_host : "") };
      });
    }).catch(function () { return []; });
  }
  function startScan(host) {
    say("Starting a scan of " + host + "…");
    var headers = { "Content-Type": "application/json", Accept: "application/json" };
    if (token) headers.Authorization = "Bearer " + token;
    fetch("/scans", { method: "POST", credentials: "same-origin", headers: headers, body: JSON.stringify({ targets: [host] }) })
      .then(function (r) { return r.json().then(function (b) { if (!r.ok) throw new Error(b.detail || ("HTTP " + r.status)); return b; }); })
      .then(function (s) { location.href = "/scan/" + enc(s.id); })
      .catch(function (e) { say("The scan of " + host + " did not start: " + e.message); });
  }

  function optionsHtml(list, sel) {
    if (!list.length) return '<div class="i-empty">Nothing matches. A domain looks like <code>example.com</code>; an algorithm like <code>ML-KEM</code> or <code>secp256r1</code>; a commit is 7 to 40 hex characters.</div>';
    return list.map(function (o, i) {
      return '<a class="i-opt" role="option" id="opt-' + i + '" data-i="' + i + '" data-kind="' + esc(o.kind) + '" aria-selected="' + (i === sel) + '" href="' + esc(o.h) + '"' + (o.ext ? ' rel="noopener" target="_blank"' : "") + '>' +
        '<span class="k">' + esc(o.kind) + '</span><span class="t">' + esc(o.t) + '</span><span class="h">' + esc(o.hint || "") + "</span></a>";
    }).join("");
  }
  /* Wire an input to a list of options. Enter opens the selected one. */
  function bindRecognizer(input, listEl, onGo) {
    var sel = 0, view = [], seq = 0;
    function draw() { sel = Math.min(sel, Math.max(0, view.length - 1)); listEl.innerHTML = optionsHtml(view, sel); input.setAttribute("aria-activedescendant", view.length ? "opt-" + sel : ""); }
    function paint() {
      view = recognize(input.value); draw();
      var mine = ++seq;
      searchMine(input.value.trim()).then(function (extra) { if (mine === seq && extra.length) { view = view.concat(extra.filter(function (x) { return !view.some(function (v) { return v.h === x.h; }); })); draw(); } });
    }
    input.addEventListener("input", function () { sel = 0; paint(); });
    input.addEventListener("focus", function () { listEl.hidden = false; });
    input.addEventListener("blur", function () { setTimeout(function () { if (!input.value && document.activeElement !== input) listEl.hidden = true; }, 200); });
    listEl.hidden = document.activeElement !== input && !input.value;
    input.addEventListener("keydown", function (e) {
      if (e.key === "ArrowDown") { e.preventDefault(); sel = (sel + 1) % Math.max(1, view.length); draw(); }
      else if (e.key === "ArrowUp") { e.preventDefault(); sel = (sel - 1 + view.length) % Math.max(1, view.length); draw(); }
      else if (e.key === "Enter") { e.preventDefault(); if (view[sel]) { if (onGo) onGo(); go(view[sel]); } }
    });
    listEl.addEventListener("click", function (e) { var a = e.target.closest(".i-opt"); if (!a) return; var o = view[+a.getAttribute("data-i")]; if (o && (o.run || o.h === "#")) { e.preventDefault(); if (onGo) onGo(); go(o); } });
    paint();
    Promise.all([workspace(), connection()]).then(function (r) { WS = r[0]; CONN = r[1]; if (!input.value) paint(); });
    return paint;
  }
  function go(o) { if (o.run) o.run(); else if (o.h === "#") return; else if (o.ext) window.open(o.h, "_blank", "noopener"); else location.href = o.h; }

  /* ⌘K / Ctrl+K / "/" opens the command bar over any view. */
  function openPalette() {
    if ($(".i-pal-back")) return;
    var back = document.createElement("div");
    back.className = "i-pal-back";
    back.innerHTML = '<div class="i-pal" role="dialog" aria-modal="true" aria-label="Go to">' +
      '<div class="i-field"><span class="p" aria-hidden="true">&rsaquo;</span><input id="pal-q" type="text" autocomplete="off" spellcheck="false" role="combobox" aria-expanded="true" aria-controls="pal-l" placeholder="A domain, an algorithm, a CVE, a commit, a page"></div>' +
      '<div class="i-opts" id="pal-l" role="listbox"></div>' +
      '<div class="i-pal-foot"><span><kbd>&uarr;</kbd><kbd>&darr;</kbd> choose</span><span><kbd>Enter</kbd> open</span><span><kbd>Esc</kbd> close</span></div></div>';
    document.body.appendChild(back);
    var close = function () { back.remove(); document.removeEventListener("keydown", esc_); };
    var esc_ = function (e) { if (e.key === "Escape") close(); };
    document.addEventListener("keydown", esc_);
    back.addEventListener("click", function (e) { if (e.target === back) close(); });
    bindRecognizer($("#pal-q", back), $("#pal-l", back), close);
    $("#pal-q", back).focus();
  }
  document.addEventListener("keydown", function (e) {
    var typing = /input|textarea|select/i.test((document.activeElement || {}).tagName || "");
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); openPalette(); }
    else if (e.key === "/" && !typing) { e.preventDefault(); openPalette(); }
  });

  /* ── the connection readout: this browser's own handshake with Morrow ──── */
  // Cloudflare, in front of morrow.soqlab.com, answers /cdn-cgi/trace on this origin with key=value
  // lines, among them kex=, the key exchange this browser negotiated. One request per page load.
  // Where the path does not exist (a self-hosted copy, local development) the answer is "unknown".
  var connP = null;
  function connection() {
    if (!connP) {
      connP = fetch("/cdn-cgi/trace", { cache: "no-store", credentials: "omit" })
        .then(function (r) { if (!r.ok || (r.headers.get("content-type") || "").indexOf("text/plain") !== 0) throw new Error("none"); return r.text(); })
        .then(function (t) {
          var kv = {}; t.split("\n").forEach(function (l) { var i = l.indexOf("="); if (i > 0) kv[l.slice(0, i).trim()] = l.slice(i + 1).trim(); });
          if (!kv.kex) return { status: "unknown", tls: kv.tls || null, http: kv.http || null };
          return { status: /mlkem|kyber/i.test(kv.kex) ? "pq" : "classical", kex: kv.kex, tls: kv.tls || null, http: kv.http || null };
        })
        .catch(function () { return { status: "unknown" }; });
    }
    return connP;
  }
  var basisP = null;
  function basis() { if (!basisP) basisP = getJSON("/api/public/basis").catch(function () { return null; }); return basisP; }
  function years(b) { return b ? b.decrypt_year_low + "–" + b.decrypt_year_high : "a future year"; }
  function connSentence(c, b) {
    if (c.status === "pq") return byDepth({
      plain: "Your connection to Morrow right now is protected against future quantum computers.",
      standard: "Your browser and Morrow agreed on " + c.kex + ", a post-quantum key exchange: a recording of this session stays unreadable.",
      expert: "This session's key exchange is " + c.kex + " over " + (c.tls || "TLS") + ": the session key needs both ML-KEM-768 and X25519 broken."
    });
    if (c.status === "classical") return byDepth({
      plain: "Your connection to Morrow right now uses older encryption that a future quantum computer could read, from about " + years(b) + ".",
      standard: "Your browser and Morrow agreed on " + c.kex + ", a classical key exchange: a recording of this session could be read from about " + years(b) + ".",
      expert: "This session negotiated " + c.kex + " over " + (c.tls || "TLS") + ": no ML-KEM share, so the session key falls to Shor's algorithm. Your browser may not offer X25519MLKEM768."
    });
    return "This server's edge did not report which key exchange your connection used, so Morrow cannot show it here.";
  }
  function paintConnStrip() {
    var strip = $("#i-conn"); if (!strip) return;
    Promise.all([connection(), basis()]).then(function (r) {
      var c = r[0], b = r[1];
      // Shown only where the edge in front of this server reports the key exchange (the hosted
      // service does; a self-hosted copy or local development may not): no "not reported" panel.
      if (c.status === "unknown") { strip.hidden = true; return; }
      strip.hidden = false;
      var label = c.status === "pq" ? "post-quantum" : "classical";
      strip.innerHTML = '<div class="i-conn-in"><span>Your connection to Morrow</span>' +
        (c.tls ? "<span><b>" + esc(c.tls) + "</b></span>" : "") +
        (c.kex ? "<span>key exchange <b>" + esc(c.kex) + "</b></span>" : "") +
        '<span data-s="' + esc(c.status) + '">' + esc(label) + "</span>" +
        (c.status === "classical" && b ? "<span>readable from about " + esc(years(b)) + "</span>" : "") +
        (c.kex ? '<a href="/algorithms/' + (c.status === "pq" ? "x25519mlkem768" : "x25519") + '">what this means</a>' : "") + "</div>";
    });
  }

  /* ── the frame ─────────────────────────────────────────────────────────── */
  var main = $("#main");
  var SECTORS = null;
  function say(text) { var el = $("#say"); if (el) el.textContent = text; }
  function setView(channel, title) {
    document.title = title ? title + " · Morrow" : "Morrow";
    document.body.setAttribute("data-ch", channel);
  }
  function status(el, text, tone) { if (!el) return; el.textContent = text || ""; if (tone) el.setAttribute("data-tone", tone); else el.removeAttribute("data-tone"); }
  /* A labelled section. The first argument used to be a channel number; sections are named only. */
  function panel(n, title, body, extra) {
    return '<section class="ch"' + (extra && extra.ch ? ' data-ch="' + extra.ch + '"' : "") + (extra && extra.id ? ' id="' + extra.id + '"' : "") + '><div class="ch-head"><span>' + esc(title) + "</span>" +
      (extra && extra.right ? '<span class="ch-r">' + extra.right + "</span>" : "") + '</div><div class="ch-body">' + body + "</div></section>";
  }
  function reading(k, v, cls) { return '<div class="reading"><dt>' + esc(k) + '</dt><dd class="' + (cls || "") + '">' + v + "</dd></div>"; }
  function gradeChip(g) { return g ? '<span class="g-chip" data-g="' + esc(g) + '">' + esc(g) + "</span>" : '<span class="g-chip">-</span>'; }
  /* Motion only for a real event: the element that changed is lit once. */
  function flash(el) { if (!el) return; el.classList.remove("flash"); void el.offsetWidth; el.classList.add("flash"); }
  function dial() {
    var box = $("#i-dial"); if (!box) return;
    box.innerHTML = DEPTHS.map(function (d) { return '<button type="button" data-d="' + d + '" aria-pressed="' + (d === depth) + '">' + d + "</button>"; }).join("");
    box.addEventListener("click", function (e) {
      var b = e.target.closest("button[data-d]"); if (!b) return;
      depth = b.getAttribute("data-d"); LS.set("morrow_depth", depth);
      setParam("depth", depth === "standard" ? null : depth);
      $$("button", box).forEach(function (x) { x.setAttribute("aria-pressed", String(x.getAttribute("data-d") === depth)); });
      paintConnStrip(); route();
    });
  }
  function footer() {
    var f = $("#i-build"); if (!f) return;
    getJSON("/api/public/build").then(function (b) {
      if (!b || !b.commit) { f.innerHTML = 'This server did not report which commit it runs. <a href="/trust">Why that matters</a>'; return; }
      f.innerHTML = 'This server runs commit <a href="/trust"><b>' + esc(b.commit_short || b.commit.slice(0, 12)) + '</b></a> of <a href="' + esc(b.commit_url) + '" rel="noopener">soqlab/Morrow</a>' +
        ' &middot; <a href="/trust">check it</a>';
    }).catch(function () { f.textContent = "Could not read which commit this server runs."; });
  }

  /* The grade of an endpoint your organisation scanned, by the same rubric as the public grade
     (services/public_grade.py, docs/PUBLIC_GRADE.md), read from the scan's own facts:
     A post-quantum key exchange and nothing weak; B post-quantum with a weakness left;
     C TLS 1.3 classical; D TLS 1.2 at best; E legacy protocols or weak ciphers;
     F an invalid certificate or a negotiated key exchange without forward secrecy (RSA key
     transport offered only as a fallback is a weakness, as in the public rubric). Null without TLS. */
  function scanGrade(r) {
    if (!r || r.error || (r.scan_status && r.scan_status !== "ok") || !r.tls_version) return null;
    var w = r.decrypt_window || {};
    var versions = (r.tls_supported_versions || []).concat([r.tls_version]).map(function (v) { return String(v).replace(/^TLSv?/i, ""); });
    var legacy = versions.indexOf("1.0") >= 0 || versions.indexOf("1.1") >= 0;
    var tls13 = versions.indexOf("1.3") >= 0;
    var weak = (r.tls12_weak_accepted_ciphers || []).length > 0;
    var rsaFallback = (w.notes || []).some(function (n) { return /RSA key transport/.test(n); });
    var expiring = r.days_until_expiry != null && r.days_until_expiry >= 0 && r.days_until_expiry < 14;
    var negotiatedFs = /1\.3/.test(r.tls_version) || /DHE/i.test(r.cipher_name || "");
    if (r.verify_error || (r.days_until_expiry != null && r.days_until_expiry < 0) || !negotiatedFs) return "F";
    if (w.status === "protected") return legacy || weak || rsaFallback || expiring ? "B" : "A";
    if ((legacy && !tls13) || weak) return "E";
    return tls13 ? "C" : "D";
  }
  /* What to say beside a grade. When the grade is set by something other than quantum
     readability (an untrusted certificate, no forward secrecy), say that, in a warning colour,
     never a reassuring "protected" next to a failing grade. */
  function endpointStatus(r) {
    var w = (r && r.decrypt_window) || {};
    if (!r || !r.tls_version) return '<span class="i-dim">no TLS seen</span>';
    if (r.days_until_expiry != null && r.days_until_expiry < 0) return '<span class="v-bad">certificate expired</span>';
    if (r.verify_error) return '<span class="v-bad" title="' + esc(r.verify_error) + '">certificate not trusted</span>';
    if (!(/1\.3/.test(r.tls_version) || /DHE/i.test(r.cipher_name || ""))) return '<span class="v-bad">no forward secrecy</span>';
    if (w.status === "at_risk") return '<span class="v-warn">readable from ' + esc(w.readable_from) + "</span>";
    if (w.status === "protected") {
      var g = scanGrade(r);
      return g === "A" ? '<span class="v-ok">protected</span>' : '<span class="v-ok">protected</span> <span class="v-warn">with a weakness</span>';
    }
    return '<span class="i-dim">key exchange not observed</span>';
  }
  function sinceWhen(iso) {
    var d = new Date(iso), now = new Date();
    if (isNaN(d)) return "";
    if (d.toISOString().slice(0, 10) === now.toISOString().slice(0, 10)) return d.toISOString().slice(11, 16) + " UTC today";
    if (now - d < 30 * 86400000) return d.toLocaleString("en-GB", { day: "numeric", month: "long", timeZone: "UTC" });
    return monthName(iso);
  }
  var ORDER = { A: 0, B: 1, C: 2, D: 3, E: 4, F: 5 };
  function gOrd(g) { return g in ORDER ? ORDER[g] : -1; }
  function typical(grades) {
    var g = grades.filter(Boolean).sort(function (a, b) { return ORDER[a] - ORDER[b]; });
    return g.length ? g[Math.floor((g.length - 1) / 2)] : null;
  }
  function rTarget(r) { return r.asset_key || (r.host ? r.host + ":" + (r.port || 443) : r.target || ""); }
  function hostOf(key) { return String(key || "").replace(/:\d+$/, ""); }
  function registrable(host) { var p = String(host).split("."); return p.length > 2 ? p.slice(-2).join(".") : host; }

  /* The workspace's history: every finished scan with its results, oldest first, and the estate
     (latest result per endpoint) as it stood after each scan. Real data only. */
  var historyP = null;
  function estateHistory() {
    if (historyP) return historyP;
    historyP = workspace().then(function (w) {
      if (!w) return null;
      var done = w.scans.filter(function (s) { return /done|completed/i.test(s.status || ""); })
        .sort(function (a, b) { return String(a.created_at).localeCompare(String(b.created_at)); }).slice(-40);
      return Promise.all(done.map(function (s) {
        return getJSON("/scans/" + enc(s.id) + "/results", { auth: token }).catch(function () { return null; });
      })).then(function (all) {
        var points = [], current = {};
        all.forEach(function (sc, i) {
          if (!sc) return;
          (sc.results || []).forEach(function (r) { var k = rTarget(r); if (k) current[k] = { r: r, scan: done[i].id, at: sc.created_at }; });
          var snapshot = {}; Object.keys(current).forEach(function (k) { snapshot[k] = current[k]; });
          points.push({ id: done[i].id, at: sc.created_at, estate: snapshot });
        });
        return { points: points, running: w.scans.filter(function (s) { return /queued|running|pending/i.test(s.status || ""); }) };
      });
    });
    return historyP;
  }
  function estateFacts(estate) {
    var keys = Object.keys(estate);
    var grades = keys.map(function (k) { return scanGrade(estate[k].r); });
    var atRisk = keys.filter(function (k) { return (estate[k].r.decrypt_window || {}).status === "at_risk"; });
    var counts = {}; grades.forEach(function (g) { if (g) counts[g] = (counts[g] || 0) + 1; });
    return { keys: keys, grades: grades, atRisk: atRisk, counts: counts, typical: typical(grades) };
  }
  function monthName(iso) { var d = new Date(iso); return isNaN(d) ? "" : d.toLocaleString("en-GB", { month: "long", year: "numeric", timeZone: "UTC" }); }
  function estateSentence(H, at) {
    var pts = H.points; if (!pts.length) return null;
    var idx = at == null ? pts.length - 1 : at;
    var now = estateFacts(pts[idx].estate), first = estateFacts(pts[0].estate);
    var n = now.keys.length, risky = now.atRisk.length;
    var trend = idx > 0 && first.typical && now.typical && first.typical !== now.typical
      ? (ORDER[now.typical] < ORDER[first.typical] ? " Typical grade went from " + first.typical + " to " + now.typical : " Typical grade slipped from " + first.typical + " to " + now.typical) + " since " + sinceWhen(pts[0].at) + "." : "";
    if (!trend && idx > 0) {
      // The typical grade can hold still while endpoints move: count the moves themselves.
      var up = 0, down = 0;
      Object.keys(pts[idx].estate).forEach(function (k) {
        if (!pts[0].estate[k]) return;
        var a = scanGrade(pts[0].estate[k].r), b = scanGrade(pts[idx].estate[k].r);
        if (a && b && a !== b) { if (ORDER[b] < ORDER[a]) up++; else down++; }
      });
      if (up || down) trend = " Since " + sinceWhen(pts[0].at) + ": " + (up ? up + " endpoint" + (up === 1 ? "" : "s") + " improved" : "") + (up && down ? ", " : "") + (down ? down + " got worse" : "") + ".";
    }
    return byDepth({
      plain: risky ? risky + " of your " + n + " endpoint" + (n === 1 ? "" : "s") + " send traffic a future quantum computer could read." + trend
                   : "All " + n + " of your scanned endpoint" + (n === 1 ? " is" : "s are") + " protected against future quantum decryption." + trend,
      standard: n + " endpoint" + (n === 1 ? "" : "s") + (idx === pts.length - 1 ? "" : " as of " + day(pts[idx].at)) + ": " + risky + " readable from about 2035–2040, typical grade " + (now.typical || "-") + "." + trend,
      expert: n + " endpoints after scan " + String(pts[idx].id).slice(0, 8) + " (" + stamp(pts[idx].at) + "); classical key exchange on " + risky + "; grades " +
        ["A", "B", "C", "D", "E", "F"].filter(function (g) { return now.counts[g]; }).map(function (g) { return g + "×" + now.counts[g]; }).join(" ") + "." + trend
    });
  }

  /* ── views ─────────────────────────────────────────────────────────────── */
  var segs = location.pathname.replace(/\/+$/, "").split("/").filter(Boolean).map(decodeURIComponent);
  function route() {
    var s0 = segs[0] || "";
    if (!s0) return viewHome();
    if (s0 === "league") return viewLeague();
    if (s0 === "atlas") return workspace().then(function (w) { location.replace(w ? "/estate" : "/league"); });
    if (s0 === "algorithms") return segs[1] ? viewAlgorithm(segs[1]) : viewAlgorithms();
    if (s0 === "trust") return viewTrust();
    if (s0 === "watching" && window.MorrowWatch) return window.MorrowWatch.watching();
    if (s0 === "about-scanner" && window.MorrowWatch) return window.MorrowWatch.aboutScanner();
    if (s0 === "estate") return segs[1] === "scan" && segs[2] ? viewScan(segs[2]) : segs[1] === "asset" && segs[2] ? viewAsset(segs.slice(2).join("/")) : viewEstate();
    var d = asDomain(s0);
    if (d && segs.length === 1) return viewDomain(d);
    setView("grade", "Not found");
    say("There is nothing at this address. Type what you were looking for.");
    main.innerHTML = inputBlock("nf-q");
    bindRecognizer($("#nf-q"), $("#nf-q-l"));
  }
  function inputBlock(id) {
    return '<label class="sr-only" for="' + id + '">A domain, an algorithm, a CVE, a commit, or a command such as scan example.com</label>' +
      '<div class="i-field"><span class="p" aria-hidden="true">&rsaquo;</span><input id="' + id + '" type="text" autocomplete="off" spellcheck="false" inputmode="url" role="combobox" aria-expanded="true" aria-controls="' + id + '-l" placeholder="example.com"></div>' +
      '<div class="i-opts" id="' + id + '-l" role="listbox"></div>';
  }

  /* Home: the one input and a live reading. Signed in, the reading is your estate. */
  function viewHome() {
    setView("grade", null);
    say(byDepth({ plain: "Type a website's address to see whether traffic to it could be read by a future quantum computer, and how to fix it.",
      standard: "Type a domain, an algorithm, a CVE or a commit. A domain gets its answer, its grade and the fix.",
      expert: "Hostname → grade (rubric on /api/public); algorithm → reference; CVE → NVD; hex → commit check; “scan host” → your workspace." }));
    main.innerHTML = inputBlock("home-q") + '<p class="i-fine" id="home-hint">The address works too: <code>' + esc(location.host) + '/example.com</code>.</p><div id="home-reading"></div>';
    bindRecognizer($("#home-q"), $("#home-q-l"));
    $("#home-q").addEventListener("input", function () { $("#home-hint").hidden = !!this.value; });
    $("#home-q").focus();
    workspace().then(function (w) { return w ? homeSignedIn() : homePublic(); });
  }
  function homePublic() {
    var box = $("#home-reading");
    box.innerHTML = '<div class="ch-grid"><div class="span-12">' + panel("", "Checked on this server", '<dl class="readouts" id="home-stats"></dl><p class="i-fine" id="home-stats-n"></p>', { ch: "league" }) + "</div>" +
      '<div class="span-12">' + panel("", "By sector", '<div id="home-sectors" class="i-muted">Reading&hellip;</div>', { ch: "league", right: '<a href="/league">trend over time</a>' }) + "</div></div>";
    getJSON("/api/public/stats").then(function (s) {
      $("#home-stats").innerHTML = reading("Checks, 7 days", num(s.public_checks_7d)) + reading("Domains checked", num(s.domains_checked)) +
        reading("Post-quantum, 7 days", pct(s.pq_share_7d), "v-ok");
      $("#home-stats-n").textContent = depth === "expert" ? "From this server's stored results at " + stamp(s.generated_at) + ", rubric " + s.rubric_version + "." : "";
    }).catch(function (e) { $("#home-stats").innerHTML = '<div class="i-empty">' + esc(e.message) + "</div>"; });
    getJSON("/api/public/league").then(function (L) { $("#home-sectors").innerHTML = sectorRows(L.sectors || [], false); paintBars(); })
      .catch(function (e) { $("#home-sectors").textContent = e.message; });
  }
  function homeSignedIn() {
    var box = $("#home-reading");
    box.innerHTML = panel("", "Your estate", '<div id="home-estate" class="i-muted">Reading your scans&hellip;</div>', { ch: "grade", right: '<a href="/estate">through time</a>' });
    estateHistory().then(function (H) {
      if (!H || !H.points.length) {
        say("Nothing in your workspace has been scanned yet. Type “scan” and one of your domains to take the first reading.");
        $("#home-estate").innerHTML = '<p>Your estate is empty. Try <code>scan ' + esc(recent().filter(function (r) { return r.kind === "domain"; }).map(function (r) { return r.id; })[0] || "your-domain.com") + '</code> in the input above.</p>';
        return;
      }
      say(estateSentence(H));
      $("#home-estate").innerHTML = scrubberHtml(H, H.points.length - 1) + estateGrid(H.points[H.points.length - 1].estate, 12);
      $("#home-estate .scrub").addEventListener("click", function (e) { var b = e.target.closest("button[data-i]"); if (b) location.href = "/estate?at=" + enc(H.points[+b.getAttribute("data-i")].id); });
    });
  }

  /* An endpoint list grouped by domain, worst first. */
  function estateGrid(estate, limit) {
    var keys = Object.keys(estate).sort(function (a, b) { return gOrd(scanGrade(estate[b].r)) - gOrd(scanGrade(estate[a].r)) || a.localeCompare(b); });
    var shown = limit ? keys.slice(0, limit) : keys;
    var rows = shown.map(function (k) {
      var r = estate[k].r, w = r.decrypt_window || {};
      return "<tr><td>" + gradeChip(scanGrade(r)) + '</td><td><a href="/estate/asset/' + enc(k) + '">' + esc(k) + "</a></td><td>" + endpointStatus(r) +
        (depth === "expert" ? '</td><td class="mono">' + esc(r.key_exchange || "-") + " · " + esc(r.tls_version || "-") : "") + '</td><td class="mono i-dim">' + esc(day(estate[k].at)) + "</td></tr>";
    }).join("");
    return '<div class="i-table-wrap"><table class="i-table"><tbody>' + rows + "</tbody></table></div>" +
      (limit && keys.length > limit ? '<p class="i-fine"><a href="/estate">All ' + keys.length + " endpoints</a></p>" : "");
  }
  function scrubberHtml(H, idx) {
    return '<div class="scrub" id="es-scrub" role="listbox" tabindex="0" aria-label="Your scans, oldest to newest. Arrow keys or scrolling move through time.">' +
      H.points.map(function (p, i) {
        var f = estateFacts(p.estate);
        return '<button type="button" role="option" data-i="' + i + '" data-g="' + esc(f.typical || "") + '" aria-current="' + (i === idx) + '" title="' + esc(stamp(p.at) + ": typical grade " + (f.typical || "-") + ", " + f.keys.length + " endpoints") + '"><i></i></button>';
      }).join("") + "</div>";
  }

  /* Your estate through time: the main signed-in view. */
  function viewEstate() {
    setView("grade", "Your estate");
    say("Reading your scans…");
    main.innerHTML = inputBlock("es-q") + '<div id="es-body"></div>';
    bindRecognizer($("#es-q"), $("#es-q-l"));
    estateHistory().then(function (H) {
      if (!H) { say("Sign in to see your estate."); $("#es-body").innerHTML = '<p><a href="/ui/">Sign in</a>. Without an account, any single domain can still be graded: type it above.</p>'; return; }
      if (!H.points.length) { say("Nothing scanned yet. Type “scan” and one of your domains above to take the first reading."); return; }
      var at = param("at"), idx = H.points.length - 1;
      H.points.forEach(function (p, i) { if (p.id === at) idx = i; });
      function paint() {
        var p = H.points[idx], f = estateFacts(p.estate);
        say(estateSentence(H, idx));
        var big = f.keys.length > 60 && depth !== "plain";
        $("#es-body").innerHTML = panel("", "Through time", scrubberHtml(H, idx) + '<p class="i-fine">' + esc(H.points.length + " scans from " + day(H.points[0].at) + " to " + day(H.points[H.points.length - 1].at) + ". Showing the estate as it stood after the scan of " + stamp(p.at) + ".") + "</p>", { ch: "league" }) +
          (depth === "plain" ? "" : panel("", "Grades", '<dl class="readouts">' + ["A", "B", "C", "D", "E", "F"].map(function (g) { return reading(g, num(f.counts[g] || 0)); }).join("") + "</dl>", { ch: "grade" })) +
          (big ? panel("", "Map", '<div class="atlas-wrap" id="es-map"></div><p class="i-fine">Scroll or pinch to zoom; click a domain to zoom into it. Grey outlines had no TLS to grade.</p>', { ch: "atlas" }) : "") +
          panel("", "Endpoints", estateGrid(p.estate, depth === "plain" ? 10 : 0), { ch: "grade" }) +
          (H.running.length ? '<p class="i-status">' + H.running.length + " scan" + (H.running.length === 1 ? " is" : "s are") + ' still running: <a href="/estate/scan/' + enc(H.running[0].id) + '">watch it</a>.</p>' : "");
        if (big) {
          var groups = {};
          f.keys.forEach(function (k) { var dom = registrable(hostOf(k)); (groups[dom] = groups[dom] || []).push({ id: k, label: k, g: scanGrade(p.estate[k].r), href: "/estate/asset/" + enc(k) }); });
          drawAtlas($("#es-map"), Object.keys(groups).sort().map(function (dname) { return { id: dname, name: dname, cells: groups[dname] }; }));
        }
        var box = $("#es-scrub");
        box.onclick = function (e) { var b = e.target.closest("button[data-i]"); if (b) pick(+b.getAttribute("data-i")); };
        box.onwheel = function (e) { e.preventDefault(); pick(idx + (e.deltaY > 0 || e.deltaX > 0 ? 1 : -1)); };
        box.onkeydown = function (e) { if (e.key === "ArrowRight") { e.preventDefault(); pick(idx + 1); } else if (e.key === "ArrowLeft") { e.preventDefault(); pick(idx - 1); } };
        var sel = box.querySelector('[aria-current="true"]'); if (sel) sel.scrollIntoView({ block: "nearest", inline: "nearest" });
      }
      function pick(i) { i = Math.max(0, Math.min(H.points.length - 1, i)); if (i === idx) return; idx = i; setParam("at", i === H.points.length - 1 ? null : H.points[i].id); paint(); var b = $("#es-scrub"); if (b) b.focus({ preventScroll: true }); }
      paint();
    });
  }

  /* One scan: watched live until it finishes; the answer flashes once when it lands. */
  function viewScan(id) {
    setView("grade", "Scan");
    say("Reading scan " + id.slice(0, 8) + "…");
    main.innerHTML = '<div id="sc-body"></div>';
    var last = null;
    function poll() {
      getJSON("/scans/" + enc(id) + "/results", { auth: token, cache: "no-store" }).then(function (s) {
        var finished = /done|completed|failed/i.test(s.status || "");
        var results = s.results || [];
        if (!finished) {
          say("Scanning " + results.map(rTarget).concat([]).join(", ") + "… " + ((s.progress || {}).done || 0) + " of " + ((s.progress || {}).total || "?") + " done.");
          $("#sc-body").innerHTML = '<p class="i-status">Started ' + esc(ago(s.created_at)) + ". This page updates by itself when the scan finishes.</p>";
          setTimeout(poll, 2500); return;
        }
        var grades = results.map(scanGrade);
        var r0 = results[0], w0 = (r0 && r0.decrypt_window) || {};
        say(!results.length ? "The scan finished without a result." + (s.error ? " " + s.error : "") :
          results.length === 1 ? rTarget(r0) + ": grade " + (grades[0] || "-") + ". " + (w0.status === "at_risk" ? "Traffic recorded today could be read from about " + w0.readable_from + "–" + w0.readable_by + "." : w0.status === "protected" ? "Protected against future quantum decryption." : "Its key exchange was not observed.")
            : results.length + " endpoints scanned; typical grade " + (typical(grades) || "-") + ".");
        $("#sc-body").innerHTML = panel("", "Results", '<div class="i-table-wrap"><table class="i-table"><tbody>' + results.map(function (r, i) {
          var w = r.decrypt_window || {};
          return "<tr><td>" + gradeChip(grades[i]) + '</td><td><a href="/estate/asset/' + enc(rTarget(r)) + '">' + esc(rTarget(r)) + "</a></td><td>" + endpointStatus(r) + "</td><td><a href=\"/" + esc(hostOf(rTarget(r))) + '">the fix</a></td></tr>';
        }).join("") + "</tbody></table></div>" + '<p class="i-fine">Finished ' + esc(stamp(s.created_at)) + '. <a href="/estate">Your estate through time</a>.</p>', { ch: "grade" });
        if (last === "running") { flash($("#say")); flash($("#sc-body")); }
      }).catch(function (e) { say("This scan could not be read: " + e.message); });
      last = last || "running";
    }
    getJSON("/scans/" + enc(id), { auth: token, cache: "no-store" }).then(function (s) { last = /done|completed|failed/i.test(s.status || "") ? "done" : "running"; poll(); })
      .catch(function (e) { say("This scan could not be read: " + e.message); });
  }

  /* One endpoint of yours: the answer, the fix, re-scan, and its own history. */
  function viewAsset(key) {
    setView("grade", key);
    say("Reading " + key + "…");
    main.innerHTML = '<div id="as-body"></div>';
    estateHistory().then(function (H) {
      if (!H) { say("Sign in to see your own endpoints."); return; }
      var hist = H.points.filter(function (p) { return p.estate[key] && p.estate[key].scan === p.id; }).map(function (p) { return p.estate[key]; });
      if (!hist.length) { say(key + " is not in your scans yet."); $("#as-body").innerHTML = '<button type="button" class="i-btn solid" id="as-scan">Scan ' + esc(hostOf(key)) + "</button>"; $("#as-scan").onclick = function () { startScan(hostOf(key)); }; return; }
      var r = hist[hist.length - 1].r, w = r.decrypt_window || {}, g = scanGrade(r), host = hostOf(key);
      say(key + ": " + (w.status === "at_risk" ? "traffic recorded today could be read from about " + w.readable_from + "–" + w.readable_by + "." : w.status === "protected" ? "protected against future quantum decryption." : "its key exchange was not observed.") +
        (g && ORDER[g] > 0 ? " The exact configuration change is on its grade page." : ""));
      var what = '<div class="i-answer"><div class="grade" data-g="' + esc(g || "") + '">' + esc(g || "-") + '</div><div><p>' + esc(r.pq_recommendation || r.quantum_safe_claim_explanation || "") + '</p><div class="i-row"><a class="i-btn solid" href="/' + esc(host) + '">The fix for this server</a><button type="button" class="i-btn" id="as-scan">Re-scan</button></div></div></div>';
      var evidence = '<dl class="readouts">' + reading("Key exchange", esc(r.key_exchange || "not observed"), w.status === "protected" ? "v-ok" : "v-warn") + reading("Protocol", esc(r.tls_version || "-")) +
        reading("Certificate", esc((r.key_type || "-") + " " + (r.key_detail || "")) + "<br><small>expires " + esc(day(r.not_after)) + "</small>") + reading("Signature", esc(r.sig_algorithm || r.signature_algorithm || "-")) + "</dl>" +
        (w.basis ? '<p class="i-fine">' + esc(w.basis) + (w.source_url ? ' <a href="' + esc(w.source_url) + '" rel="noopener">source</a>' : "") + "</p>" : "") + (w.notes || []).map(function (n) { return '<p class="i-fine">' + esc(n) + "</p>"; }).join("");
      var times = '<div class="i-table-wrap"><table class="i-table"><tbody>' + hist.slice().reverse().map(function (h) { return "<tr><td>" + gradeChip(scanGrade(h.r)) + '</td><td class="mono">' + esc(stamp(h.at)) + '</td><td class="mono">' + esc(h.r.key_exchange || "-") + '</td><td><a href="/estate/scan/' + enc(h.scan) + '">scan</a></td></tr>'; }).join("") + "</tbody></table></div>";
      $("#as-body").innerHTML = panel("", "What to do", what, { ch: "tools" }) + (depth === "plain" ? "" : panel("", "Its history", times, { ch: "league" })) + (depth === "expert" ? panel("", "Evidence", evidence, { ch: "conn" }) : "");
      $("#as-scan").onclick = function () { startScan(host); };
    });
  }

  /* A domain, public: the answer first, then what to do, then the evidence. */
  /* ── the harvest clock ──────────────────────────────────────────────────
     Will what is sent today still be secret as long as it has to be? Mosca's inequality, read from
     the domain's own scan: x years the data must stay secret, y years to finish switching, z years
     until a quantum computer can break the key exchange. The same arithmetic as
     services/decrypt_window.harvest, which the tests pin; it runs here so the dials answer at once. */
  function harvestClock(tls, pq, x, y, zYear, year) {
    var z = zYear;
    var secretUntil = year + x;
    var out = { year: year, x: x, y: y, z: z, secretUntil: secretUntil };
    if (!tls) { out.harvestable = true; out.readableFrom = year; out.short = x; out.margin = 0; out.exposed = x > 0; out.mosca = x > 0; return out; }
    if (pq) { out.harvestable = false; out.readableFrom = null; out.short = 0; out.margin = null; out.exposed = false; out.mosca = false; return out; }
    out.harvestable = true; out.readableFrom = z;
    out.short = Math.max(0, secretUntil - z);
    out.margin = Math.max(0, z - secretUntil);
    out.exposed = secretUntil > z;
    out.lastUntil = secretUntil + y;
    out.shortAfter = Math.max(0, out.lastUntil - z);
    out.mosca = x + y > z - year;
    return out;
  }
  var SHELF_EXAMPLES = [[1, "sessions, one-time codes"], [7, "financial records"], [10, "customer data"], [25, "health records"], [50, "state secrets"]];
  function yrs(n) { return n + " year" + (n === 1 ? "" : "s"); }
  function harvestState(est) {
    var year = new Date().getUTCFullYear();
    var keep = parseInt(param("keep") || LS.get("morrow_keep", "10"), 10);
    if (isNaN(keep)) keep = 10;
    var q = parseInt(param("qday") || "", 10);
    if (isNaN(q)) q = est.low;
    var sw = parseInt(param("switch") || "1", 10);
    if (isNaN(sw)) sw = 1;
    return { year: year, keep: Math.max(0, Math.min(50, keep)), qday: Math.max(est.low, Math.min(est.high, q)), sw: Math.max(0, Math.min(10, sw)) };
  }
  function harvestSentence(d, r, h, est) {
    var kx = r.key_exchange || {}, group = kx.group || "a classical group";
    if (!h.harvestable) return byDepth({
      plain: "Traffic captured today can't be read later: " + d + " uses a post-quantum key exchange. Data that must stay private until " + h.secretUntil + " stays private on this connection.",
      standard: "Traffic captured today stays unreadable: " + d + " negotiated " + group + ", so a recording kept until " + h.secretUntil + " or beyond cannot be decrypted with a quantum computer.",
      expert: "Not harvestable: " + group + " includes ML-KEM (FIPS 203). Mosca's z does not bound x for this handshake; x = " + h.x + " (until " + h.secretUntil + ") is safe against Shor."
    });
    if (h.readableFrom === h.year) return "Nothing is encrypted: traffic captured today can be read today, and your data needs to stay private until " + h.secretUntil + ".";
    var when = h.z === est.low ? "around " + h.z : h.z === est.likely ? "around " + h.z + " (the likely estimate)" : "around " + h.z;
    var tail = h.exposed ? " — " + yrs(h.short) + " short." : ", so it makes it, with " + yrs(h.margin) + " to spare.";
    return byDepth({
      plain: "Traffic captured today could be read " + when + ". Your data needs to stay private until " + h.secretUntil + tail,
      standard: "Traffic to " + d + " captured today could be read " + when + ", once a quantum computer breaks " + group + ". Data that must stay private for " + yrs(h.x) + " has to last until " + h.secretUntil + tail,
      expert: "Mosca: x + y " + (h.mosca ? ">" : "≤") + " z with x = " + h.x + ", y = " + h.y + ", z = " + (h.z - h.year) + " (CRQC " + h.z + "; " + group + " is classical). Today's traffic: " +
        (h.exposed ? yrs(h.short) + " short" : yrs(h.margin) + " spare") + ". Data sent until " + (h.year + h.y) + ", when the switch is done, must last until " + h.lastUntil + ": " + (h.shortAfter ? yrs(h.shortAfter) + " short." : "inside the window.")
    });
  }
  function harvestPanelHtml(est) {
    var examples = SHELF_EXAMPLES.map(function (e) { return '<button type="button" class="i-btn hv-ex" data-keep="' + e[0] + '">' + e[0] + " y: " + esc(e[1]) + "</button>"; }).join("");
    return panel("", "Harvest clock", '<p class="i-big hv-say" id="hv-say" aria-live="polite"></p>' +
      '<div class="hv-dials">' +
      '<div class="hv-dial"><label for="hv-keep">How long the data must stay private</label><input type="range" id="hv-keep" min="0" max="50" step="1"><output id="hv-keep-o" for="hv-keep"></output>' +
      (depth === "plain" ? "" : '<div class="i-row hv-exs" aria-label="Examples">' + examples + "</div>") + "</div>" +
      '<div class="hv-dial"><label for="hv-q">When a quantum computer can break it (estimate)</label><input type="range" id="hv-q" min="' + est.low + '" max="' + est.high + '" step="1" list="hv-q-marks"><output id="hv-q-o" for="hv-q"></output>' +
      '<datalist id="hv-q-marks"><option value="' + est.low + '" label="low"></option><option value="' + est.likely + '" label="likely"></option><option value="' + est.high + '" label="high"></option></datalist></div>' +
      (depth === "expert" ? '<div class="hv-dial"><label for="hv-sw">Years to finish switching (y)</label><input type="range" id="hv-sw" min="0" max="10" step="1"><output id="hv-sw-o" for="hv-sw"></output></div>' : "") +
      "</div>" +
      '<div class="hv-line" id="hv-line" aria-hidden="true"><i class="hv-band" id="hv-band"></i><i class="hv-gap" id="hv-gap"></i><i class="hv-mark hv-z" id="hv-z"><b></b></i><i class="hv-mark hv-u" id="hv-u"><b></b></i><span class="hv-a0" id="hv-a0"></span><span class="hv-a1" id="hv-a1"></span></div>' +
      '<p class="i-fine" id="hv-src"></p>', { ch: "conn", id: "hv" });
  }
  function bindHarvest(d, r, est, sourceUrl) {
    var box = $("#hv"); if (!box) return;
    var st = harvestState(est), ex = r.exposure || {}, kx = r.key_exchange || {};
    var tls = !!(r.tls && r.tls.negotiated), pq = !!kx.post_quantum;
    if (!tls && ex.recorded_traffic_at_risk === false) tls = true;
    var keep = $("#hv-keep", box), q = $("#hv-q", box), sw = $("#hv-sw", box);
    keep.value = st.keep; q.value = st.qday; if (sw) sw.value = st.sw;
    // The quantum year matters only to a classical exchange.
    q.disabled = pq || !tls;
    function place(el, yr, lo, hi) { var f = Math.max(0, Math.min(1, (yr - lo) / (hi - lo))); el.style.left = (f * 100).toFixed(2) + "%"; el.classList.toggle("flip", f > 0.55); }
    function paint() {
      var x = +keep.value, z = +q.value, y = sw ? +sw.value : st.sw;
      var h = harvestClock(tls, pq, x, y, z, st.year);
      $("#hv-say", box).textContent = harvestSentence(d, r, h, est);
      box.setAttribute("data-exposed", String(!!h.exposed));
      $("#hv-keep-o", box).textContent = yrs(x) + ", until " + h.secretUntil;
      $("#hv-q-o", box).textContent = pq ? "no effect on " + (kx.group || "this exchange") : z + (z === est.low ? ": low, " + est.low_label : z === est.likely ? ": likely, " + est.likely_label : z === est.high ? ": high, " + est.high_label : "");
      if (sw) $("#hv-sw-o", box).textContent = yrs(y) + ", done in " + (st.year + y);
      var lo = st.year, hi = Math.max(est.high, h.secretUntil + (depth === "expert" ? y : 0)) + 2;
      var band = $("#hv-band", box); place(band, est.low, lo, hi); band.style.width = ((est.high - est.low) / (hi - lo) * 100).toFixed(2) + "%";
      var zm = $("#hv-z", box), um = $("#hv-u", box), gap = $("#hv-gap", box);
      place(zm, z, lo, hi); place(um, h.secretUntil, lo, hi);
      zm.hidden = pq || !tls;
      $("b", zm).textContent = "readable " + z;
      $("b", um).textContent = "private until " + h.secretUntil;
      gap.hidden = !h.exposed || h.readableFrom == null;
      if (!gap.hidden) { place(gap, h.readableFrom, lo, hi); gap.style.width = ((h.secretUntil - h.readableFrom) / (hi - lo) * 100).toFixed(2) + "%"; }
      $("#hv-a0", box).textContent = String(lo); $("#hv-a1", box).textContent = String(hi);
    }
    function keepUrl() {
      LS.set("morrow_keep", keep.value);
      setParam("keep", keep.value === "10" ? null : keep.value);
      setParam("qday", +q.value === est.low ? null : q.value);
      if (sw) setParam("switch", sw.value === "1" ? null : sw.value);
    }
    [keep, q, sw].forEach(function (el) { if (!el) return; el.addEventListener("input", paint); el.addEventListener("change", keepUrl); });
    $$(".hv-ex", box).forEach(function (b) { b.addEventListener("click", function () { keep.value = b.getAttribute("data-keep"); paint(); keepUrl(); }); });
    $("#hv-src", box).innerHTML = (pq ? "Read from this check's key exchange, " + esc(kx.group || "") + ". " : tls ? "Read from this check's key exchange, " + esc(kx.group || "not observed, so treated as classical") + ". " : "") +
      "The quantum year is an estimate, not a fact: " + esc(est.low) + " (low) to " + esc(est.likely) + " (likely) are from the " +
      '<a href="' + esc(sourceUrl) + '" rel="noopener">Global Risk Institute expert survey</a>; ' + esc(est.high) + " (high) is Morrow's outer bound. Your choices stay in the address and on this device.";
    paint();
  }

  /* ── who else is exposing you: the outside services a domain depends on ── */
  var TP_ROLE = { payment: "payment", auth: "sign-in", form: "form target", shop: "shop", captcha: "bot check", support: "chat/support",
    analytics: "analytics", script: "script", library: "script library", embed: "embed", video: "video", maps: "maps", ads: "ads",
    social: "social", styles: "styles", fonts: "fonts", images: "images", cdn: "CDN / host", mail: "mail", other: "other" };
  function tpStatus(s) {
    if (s.status === "pq") return '<span class="v-ok">post-quantum</span>';
    if (s.status === "classical") return '<span class="v-warn">readable from ' + esc(s.readable_from || "") + "</span>";
    if (s.status === "no_tls") return '<span class="v-bad">no TLS</span>';
    if (s.status === "refused") return '<span class="v-bad">refused: internal address</span>';
    if (s.status === "unreachable") return '<span class="i-dim">no answer</span>';
    if (s.status === "not_graded") return '<span class="i-dim">mail: not graded</span>';
    if (s.status === "not_checked") return '<span class="i-dim">over the limit</span>';
    if (s.status === "skipped") return '<span class="i-dim">skipped</span>';
    return '<span class="i-dim">key exchange not seen</span>';
  }
  function tpHtml(x) {
    var list = x.services || [];
    var sm = x.summaries || {};
    var line = byDepth({ plain: sm.plain, standard: sm.standard, expert: sm.expert });
    var shown = depth === "plain" ? list.filter(function (s) { return s.status === "classical" || s.status === "no_tls"; }).slice(0, 5) : list;
    var rows = shown.map(function (s) {
      return "<tr><td>" + tpStatus(s) + '</td><td class="i-dim">' + esc(TP_ROLE[s.role] || s.role) + '</td><td><span class="mono">' + esc(s.host) + "</span>" +
        (s.vendor && s.vendor !== s.host ? ' <span class="i-dim">' + esc(s.vendor) + "</span>" : "") +
        (depth === "expert" ? '<br><small class="i-dim">' + esc(s.via || "") + (s.key_exchange ? " · " + esc(s.key_exchange) : "") + (s.tls_version ? " · " + esc(s.tls_version) : "") + "</small>" : "") +
        "</td><td>" + esc(s.fix || "") + "</td></tr>";
    }).join("");
    var c = x.counts || {};
    return '<p class="i-big tp-say" id="tp-say">' + esc(line || "") + "</p>" +
      (rows ? '<div class="i-table-wrap"><table class="i-table" id="tp-list"><thead><tr><th>Key exchange</th><th>Role</th><th>Service</th><th>What to do</th></tr></thead><tbody>' + rows + "</tbody></table></div>" : "") +
      '<div class="i-row"><button type="button" class="i-btn" id="tp-recheck">Re-check outside services</button><span class="i-fine">' +
      esc((x.cached ? "Stored result" : "Checked") + " " + stamp(x.checked_at) + ". " + (c.found || 0) + " found, " + (c.probed || 0) + " contacted" + (c.over_cap ? ", " + c.over_cap + " over the limit of " + ((x.limits || {}).max_hosts || "") : "") + ".") + "</span></div>" +
      (depth === "plain" ? "" : '<p class="i-fine">Found in ' + esc(d0(x)) + "'s homepage (scripts, styles, images, frames, form targets), its CNAME chain, its MX records and common sign-in and checkout names. " +
        "Each one gets the same key-exchange check as this page, only on public addresses." + ((x.homepage || {}).notes || []).map(function (n) { return " " + esc(n[0].toUpperCase() + n.slice(1)) + "."; }).join("") + "</p>");
  }
  function d0(x) { return x.domain || "this domain"; }

  function viewDomain(d) {
    setView("grade", d);
    remember("domain", d, d);
    say("Checking " + d + "…");
    main.innerHTML = '<p class="i-status" id="d-status" role="status" aria-live="polite">Asking Morrow\'s server to check ' + esc(d) + '. A first check opens a few TLS connections to port 443 and takes up to half a minute.</p><div id="d-body"></div>';
    var history_ = [], current = null, latest = null;
    var tp = null, tpErr = null, tpBusy = false;
    function loadTp(fresh) {
      if (tpBusy) return;
      tpBusy = true; tpErr = null;
      paintTp();
      getJSON("/api/public/exposure/" + enc(d) + (fresh ? "?fresh=1" : ""), { cache: fresh ? "no-store" : "default", timeout: 90000 })
        .then(function (x) { var before = tp; tp = x; tpBusy = false; paintTp(); if (before && fresh) flash($("#tp-say")); })
        .catch(function (e) { tpBusy = false; tpErr = e.message + (e.retryAfter ? " Try again in " + e.retryAfter + " s." : ""); paintTp(); });
    }
    function paintTp() {
      var box = $("#tp-body"); if (!box) return;
      if (tp && window.MorrowWatch) window.MorrowWatch.services(d, tp);
      if (tp) box.innerHTML = tpHtml(tp) + (tpBusy ? '<p class="i-status">Re-checking the outside services…</p>' : "") + (tpErr ? '<p class="i-status" data-tone="bad">' + esc(tpErr) + "</p>" : "");
      else if (tpErr) box.innerHTML = '<p class="i-status" data-tone="bad">' + esc(tpErr) + '</p><div class="i-row"><button type="button" class="i-btn" id="tp-recheck">Try again</button></div>';
      else box.innerHTML = '<p class="i-status" role="status">Reading ' + esc(d) + "'s homepage and DNS for the services it depends on, then checking each one's key exchange. Up to half a minute.</p>";
      var b = $("#tp-recheck"); if (b) { if (tpBusy) b.setAttribute("aria-busy", "true"); b.addEventListener("click", function () { loadTp(true); }); }
    }
    var at = param("at");

    function load(fresh) {
      if (fresh) status($("#d-status"), "Re-checking " + d + " now…");
      var btn = $("#d-recheck"); if (btn) btn.setAttribute("aria-busy", "true");
      return getJSON("/api/public/grade/" + enc(d) + (fresh ? "?fresh=1" : ""), { cache: fresh ? "no-store" : "default" })
        .then(function (r) {
          var before = latest;
          latest = r;
          return getJSON("/api/public/history/" + enc(d) + "?detail=1&limit=100", { cache: "no-store" }).catch(function () { return []; })
            .then(function (h) {
              history_ = (h || []).filter(function (x) { return x.result; }).reverse();
              if (!history_.length) history_ = [{ scanned_at: r.scanned_at, grade: r.grade, result: r }];
              var pick = at && !fresh ? history_.filter(function (x) { return x.scanned_at === at; })[0] : null;
              current = pick ? pick.result : r;
              if (fresh) setParam("at", null);
              render();
              if (!tp && !tpBusy && !tpErr) loadTp(false);
              if (fresh) {
                var changed = before && before.grade !== r.grade;
                status($("#d-status"), changed ? "Grade changed from " + before.grade + " to " + r.grade + " on this re-check." : "Re-checked " + stamp(r.scanned_at) + ": same grade, " + r.grade + ".", changed ? "ok" : null);
                if (changed) { flash($("#d-grade")); flash($("#say")); }
              }
            });
        })
        .catch(function (e) {
          var msg = e.message + (e.retryAfter ? " Try again in " + e.retryAfter + " s." : "");
          if (!latest) { say("Morrow could not grade " + d + "."); $("#d-body").innerHTML = ""; }
          status($("#d-status"), msg, "bad");
        })
        .finally(function () { var b = $("#d-recheck"); if (b) b.removeAttribute("aria-busy"); });
    }

    function answer(r) {
      var ex = r.exposure || {}, fixes = r.fixes || [], sm = r.summaries || {};
      var fixText = !fixes.length ? "Nothing to change." : fixes.length === 1 || r.platform !== "unknown"
        ? "One " + (fixes[0].applies_to && fixes[0].applies_to !== "any" ? fixes[0].applies_to + " " : "") + "change fixes it." : "One server setting fixes it; pick your server below.";
      if (depth === "expert") return d + ": grade " + r.grade + ". " + (sm.cryptographer || r.summary);
      if (ex.recorded_traffic_at_risk && ex.decrypt_year_low) return d + ": traffic recorded today could be decrypted around " + ex.decrypt_year_low + "–" + ex.decrypt_year_high + ". " + fixText;
      if (ex.recorded_traffic_at_risk) return d + ": " + (r.summary || "no encryption was negotiated.");
      return d + ": protected against future quantum decryption." + (fixes.length ? " " + (depth === "plain" ? "One housekeeping change is left." : (r.reasons || []).slice(1).join(" ")) : "");
    }

    function render() {
      var r = current, isLatest = latest && r.scanned_at === latest.scanned_at;
      var kx = r.key_exchange || {}, tls = r.tls || {}, cert = r.certificate || {}, ex = r.exposure || {};
      say(answer(r));
      status($("#d-status"), isLatest ? "Checked " + stamp(r.scanned_at) + (r.cached ? ", stored result from " + ago(r.scanned_at) : "") + "." : "Showing the check of " + stamp(r.scanned_at) + ". The newest is " + stamp(latest.scanned_at) + ".");
      var fixes = r.fixes || [];
      // Which server's change to show: the detected one, or the one picked here (kept in ?server=).
      var srvParam = (param("server") || "").toLowerCase();
      var pickIdx = 0;
      fixes.forEach(function (f, k) { if (srvParam && String(f.applies_to || "").toLowerCase() === srvParam) pickIdx = k; });
      var shown = depth === "expert" ? fixes.map(function (f, k) { return k; }) : [pickIdx];
      var picker = depth === "standard" && fixes.length > 1
        ? '<p><label for="d-srv">Your server</label> <select id="d-srv" class="i-btn">' + fixes.map(function (f, k) { return '<option value="' + k + '"' + (k === pickIdx ? " selected" : "") + ">" + esc(f.applies_to || f.title) + "</option>"; }).join("") + "</select></p>" : "";
      var fixHtml = !fixes.length ? "<p>Nothing to change.</p>" : (depth === "plain"
        ? "<p>" + esc(fixes[pickIdx].title) + ". Needs: " + esc(fixes[pickIdx].requires) + ".</p>"
        : picker + shown.map(function (k) {
          var f = fixes[k];
          return '<div class="fix"><p><b>' + esc(f.title) + '</b> <button type="button" class="i-btn" data-copy="' + k + '">Copy</button></p><pre>' + esc(f.snippet) + "</pre>" +
            (depth === "expert" && f.notes ? '<p class="i-fine">' + esc(f.notes) + "</p>" : "") + '<p class="i-fine">Needs: ' + esc(f.requires) + "</p></div>";
        }).join(""));
      var what = panel("", "What to do", fixHtml + '<div class="i-row"><button type="button" class="i-btn solid" id="d-recheck">Re-check now</button>' +
        (depth === "plain" ? "" : '<span class="i-fine">After the change, re-check: Morrow opens fresh connections instead of using the stored result.</span>') + "</div>", { ch: "tools" });
      var gradeBlock = depth === "plain" ? "" : panel("", "Grade", '<div class="i-answer"><div class="grade" id="d-grade" data-g="' + esc(r.grade) + '" aria-label="Grade ' + esc(r.grade) + '">' + esc(r.grade) + '</div><ul class="i-muted">' +
        (r.reasons || []).map(function (x) { return "<li>" + esc(x) + "</li>"; }).join("") + "</ul></div>" +
        (ex.recorded_traffic_at_risk && ex.decrypt_year_low ? '<p class="i-fine">Recorded today, readable from about ' + esc(ex.decrypt_year_low) + "–" + esc(ex.decrypt_year_high) + ': <a href="' + esc(ex.source_url) + '" rel="noopener">source</a>.</p>' : ""), { ch: "grade" });
      var evidence = "";
      if (depth === "expert") {
        var vers = ["1.3", "1.2", "1.1", "1.0"].filter(function (v) { return (tls.versions || {})[v]; });
        evidence = panel("", "Evidence", '<dl class="readouts">' +
          reading("Key exchange", esc(kx.group || "not observed"), kx.post_quantum ? "v-ok" : "v-warn") + reading("Protocol", esc(tls.negotiated || "-")) +
          reading("Versions accepted", esc(vers.join(", ") || "-")) + reading("Forward secrecy", r.forward_secrecy ? "yes" : "no", r.forward_secrecy ? "" : "v-bad") +
          reading("PQ groups accepted", esc((kx.offered_pq_groups_accepted || []).join(", ") || "none")) + reading("Certificate", esc((cert.key_type || "-") + " " + (cert.key_bits || "")) + "<br><small>expires " + esc(day(cert.not_after)) + "</small>") +
          reading("Signature", esc(cert.signature_algorithm || "-")) + reading("Served by", esc(r.server_software || r.platform || "not disclosed")) + reading("Connections opened", num(r.connections)) + "</dl>" +
          (ex.basis ? '<p class="i-fine">' + esc(ex.basis) + "</p>" : ""), { ch: "conn" }) +
          panel("", "Through time", '<div class="scrub" id="d-scrub" role="listbox" tabindex="0" aria-label="Checks of ' + esc(d) + ', oldest to newest"></div><p class="i-fine" id="d-scrub-n"></p>', { ch: "league", right: '<a href="/api/public/history/' + enc(d) + '.atom">feed of grade changes</a>' }) +
          panel("", "Badge and API", '<p><img src="/api/public/badge/' + enc(d) + '.svg" alt="quantum-ready grade badge for ' + esc(d) + '"></p>' +
            '<pre id="d-md">' + esc("[![quantum-ready](" + location.origin + "/api/public/badge/" + d + ".svg)](" + location.origin + "/" + d + ")") + '</pre><button type="button" class="i-btn" data-copy-el="d-md">Copy Markdown</button>' +
            '<pre id="d-curl">' + esc("curl " + location.origin + "/api/public/grade/" + d + ".txt") + '</pre><button type="button" class="i-btn" data-copy-el="d-curl">Copy</button>' +
            '<p class="i-fine"><a href="/r/' + enc(d) + '">Certificate-transparency record</a> &middot; <a href="/plain/' + enc(d) + '">plain</a> &middot; <a href="/api/public/grade/' + enc(d) + '">JSON</a></p>', { ch: "ref" });
      }
      var outside = panel("", "Who else is exposing you", '<div id="tp-body"></div>', { ch: "atlas", id: "tp" });
      $("#d-body").innerHTML = gradeBlock + '<div id="hv-wrap"></div>' + what + '<div id="w-wrap"></div>' + outside + evidence;
      paintTp();
      if (window.MorrowWatch) window.MorrowWatch.domain(d, latest || r);
      basis().then(function (b) {
        var wrap = $("#hv-wrap"); if (!wrap || current !== r) return;
        var est = (b && b.crqc_estimate) || { low: ex.decrypt_year_low || 2035, likely: ex.decrypt_year_high || 2040, high: (ex.decrypt_year_high || 2040) + 5,
          low_label: "quite possible", likely_label: "likely", high_label: "Morrow's outer bound" };
        wrap.innerHTML = harvestPanelHtml(est);
        bindHarvest(d, r, est, (b && b.source_url) || ex.source_url || "");
      });
      $$("[data-copy]").forEach(function (b) { b.addEventListener("click", function () { copy(fixes[+b.getAttribute("data-copy")].snippet, b); }); });
      $$("[data-copy-el]").forEach(function (b) { b.addEventListener("click", function () { copy($("#" + b.getAttribute("data-copy-el")).textContent, b); }); });
      $("#d-recheck").addEventListener("click", function () { load(true); });
      var srv = $("#d-srv");
      if (srv) srv.addEventListener("change", function () { var f = fixes[+srv.value]; setParam("server", f && f.applies_to ? String(f.applies_to).toLowerCase() : null); render(); });
      paintScrub();
    }

    function paintScrub() {
      var box = $("#d-scrub"); if (!box) return;
      box.innerHTML = history_.map(function (h, i) {
        return '<button type="button" role="option" data-i="' + i + '" data-g="' + esc(h.grade) + '" aria-current="' + (h.scanned_at === current.scanned_at) + '" title="' + esc(stamp(h.scanned_at) + ": " + h.grade) + '"><i></i></button>';
      }).join("");
      var n = history_.length, changes = history_.filter(function (h, i) { return i > 0 && history_[i - 1].grade !== h.grade; }).length;
      $("#d-scrub-n").textContent = n === 1 ? "One check stored so far." : n + " checks since " + day(history_[0].scanned_at) + ", " + changes + " grade change" + (changes === 1 ? "" : "s") + ". Scroll over the bars or use the arrow keys.";
      box.onclick = function (e) { var b = e.target.closest("button[data-i]"); if (b) pick(+b.getAttribute("data-i")); };
      box.onwheel = function (e) { if (n < 2) return; e.preventDefault(); step(e.deltaY > 0 || e.deltaX > 0 ? 1 : -1); };
      box.onkeydown = function (e) { if (e.key === "ArrowRight") { e.preventDefault(); step(1); } else if (e.key === "ArrowLeft") { e.preventDefault(); step(-1); } };
    }
    function idx() { for (var i = 0; i < history_.length; i++) if (history_[i].scanned_at === current.scanned_at) return i; return history_.length - 1; }
    function step(dl) { pick(Math.max(0, Math.min(history_.length - 1, idx() + dl))); }
    function pick(i) {
      var h = history_[i]; if (!h || h.scanned_at === current.scanned_at) return;
      current = h.result;
      setParam("at", i === history_.length - 1 ? null : h.scanned_at);
      render();
      var box = $("#d-scrub"); if (box) box.focus({ preventScroll: true });
    }
    load(false);
  }

  /* Sector averages: how each sector's graded sites are spread over A-F, and how that moved. */
  function sectorRows(sectors, withTrend) {
    var shown = sectors.filter(function (s) { return s.graded; });
    if (!shown.length) return '<p class="i-empty">No sector has graded sites on this server yet. The list is re-graded weekly, a few sites at a time.</p>';
    return '<div class="i-table-wrap"><table class="i-table"><thead><tr><th>Sector</th><th>Grades A to F</th><th class="num">Post-quantum</th>' + (withTrend ? "<th>Weekly, post-quantum share</th>" : "") + '<th class="num">Sites</th></tr></thead><tbody>' +
      shown.map(function (s) {
        var segs = ["A", "B", "C", "D", "E", "F"].map(function (g) { var n = (s.grades || {})[g] || 0; return n ? '<i class="seg" data-g="' + g + '" data-w="' + (n / s.graded) + '" title="' + g + ": " + n + '"></i>' : ""; }).join("");
        var trend = (s.trend || []).map(function (t) { return '<i class="tick" data-h="' + t.pq_share + '" title="' + esc(t.week + ": " + pct(t.pq_share) + " of " + t.graded) + '"></i>'; }).join("");
        return "<tr><td>" + esc(s.name) + '</td><td><span class="bar">' + segs + '</span></td><td class="num">' + pct(s.pq_share) + "</td>" + (withTrend ? '<td><span class="spark">' + trend + "</span></td>" : "") + '<td class="num">' + num(s.graded) + "</td></tr>";
      }).join("") + "</tbody></table></div>";
  }
  function paintBars() {
    $$(".bar .seg").forEach(function (el) { el.style.width = (Number(el.getAttribute("data-w")) * 100).toFixed(2) + "%"; });
    $$(".spark .tick").forEach(function (el) { el.style.height = Math.max(2, Number(el.getAttribute("data-h")) * 100).toFixed(1) + "%"; });
  }
  function viewLeague() {
    setView("league", "Sectors");
    say("Reading sector averages…");
    main.innerHTML = '<div id="lg-mine"></div><div id="lg-body"></div><div id="lg-ready"></div><div id="lg-not"></div>';
    getJSON("/api/public/league", { cache: "no-store" }).then(function (L) {
      SECTORS = L.sectors || [];
      var graded = L.graded, pq = 0, g = 0;
      SECTORS.forEach(function (s) { if (s.pq_share != null) { pq += s.pq_share * s.graded; g += s.graded; } });
      say(!graded ? "No site in the sector lists has been graded on this server yet." : byDepth({
        plain: pct(g ? pq / g : null) + " of " + num(graded) + " well-known sites already protect their traffic against future quantum computers.",
        standard: num(graded) + " named sites in " + SECTORS.filter(function (s) { return s.graded; }).length + " sectors graded; " + pct(g ? pq / g : null) + " negotiate a post-quantum key exchange.",
        expert: num(graded) + "/" + num(L.list_size) + " graded under rubric " + L.rubric_version + "; post-quantum share " + pct(g ? pq / g : null) + "; weekly trend from stored grades." }));
      var lr = L.last_run;
      $("#lg-body").innerHTML = panel("", "By sector", sectorRows(SECTORS, depth !== "plain"), { ch: "league", right: lr ? "last batch " + esc(ago(lr.finished_at || lr.started_at)) : "no batch has run yet" }) +
        '<p class="i-fine">Averages only: no site is named or ranked here. Each sector\'s list (in <code>backend/league/sectors.json</code>) is re-graded once a week with the same check as a domain page. Any single domain can still be checked by typing it. ' +
        (depth === "expert" ? SECTORS.filter(function (s) { return s.graded; }).map(function (s) { return "<br>" + esc(s.name) + ": " + esc(s.method); }).join("") : "") + "</p>";
      paintBars();
    }).catch(function (e) { say("The sector averages are not available right now."); $("#lg-body").innerHTML = '<div class="i-empty">' + esc(e.message) + "</div>"; });
    workspace().then(function (w) {
      if (!w) return;
      paintMine();
    });
    paintReady();
    paintNotReady();
  }

  /* Not yet post-quantum: popular sites (Tranco list only) whose newest check is below B, each
     worded as what was measured, with the date, the source and the owner's reply if any. */
  function paintNotReady() {
    var box = $("#lg-not"); if (!box) return;
    var sector = param("nr") || "";
    getJSON("/api/public/not-ready" + (sector ? "?sector=" + enc(sector) : ""), { cache: "no-store" }).then(function (N) {
      var m = N.methodology || {}, w = m.decrypt_window || {};
      var options = '<option value="">All sectors</option>' + (N.sectors || []).map(function (s) { return '<option value="' + esc(s[0]) + '"' + (s[0] === sector ? " selected" : "") + ">" + esc(s[1]) + "</option>"; }).join("");
      var rows = (N.entries || []).map(function (e) {
        return '<li class="nr" data-d="' + esc(e.domain) + '"><p>' + gradeChip(e.grade) + " " + esc(e.statement).replace(esc(e.domain), '<a href="/' + esc(e.domain) + '">' + esc(e.domain) + "</a>") +
          ' <a class="i-fine" href="' + esc(e.source_url) + '" rel="noopener">source of the years</a></p>' +
          (e.reply ? '<p class="i-fine">Reply from the owner, ' + esc(day(e.reply.at)) + ": “" + esc(e.reply.text) + "”</p>" : "") +
          '<p><button type="button" class="i-btn" data-recheck="' + esc(e.domain) + '">Re-check</button> <span class="i-status"></span></p></li>';
      }).join("");
      box.innerHTML = panel("", N.title || "Not yet post-quantum",
        '<p><label for="nr-sector">Sector</label> <select id="nr-sector" class="i-btn">' + options + "</select> " +
        '<a class="i-fine" href="/api/public/not-ready.atom' + (sector ? "?sector=" + enc(sector) : "") + '">feed of sites joining and leaving</a></p>' +
        (rows ? '<ul class="nr-list">' + rows + "</ul>" : '<p class="i-empty">No site from the list is below B on this server' + (sector ? " in this sector" : "") + ".</p>") +
        '<details class="i-fine"><summary>How this list is made</summary><p>' + esc(m.who || "") + "</p><p>" + esc(m.measured || "") + "</p><p>Rubric " + esc(m.rubric_version || "") +
        ". The years " + esc(w.low) + "–" + esc(w.high) + ' come from the <a href="' + esc(w.source_url || "") + '" rel="noopener">' + esc(w.source || "") + "</a>. " + esc(m.leaves || "") + " " + esc(m.not_a_ranking || "") +
        (m.list ? " List " + esc(m.list.list_id) + ", fetched " + esc(day(m.list.fetched_at)) + "." : "") + "</p></details>" +
        '<details class="i-fine" id="nr-correct"><summary>Request a correction</summary><form id="nr-form"><p><label>Domain <input class="i-btn" name="domain" maxlength="253" required></label></p>' +
        '<p><label>What is wrong <textarea class="i-btn" name="reason" maxlength="1000" rows="3" required></textarea></label></p>' +
        '<p><label>How to reach you <input class="i-btn" name="contact" maxlength="200" required></label></p><p><button class="i-btn" type="submit">Send</button> <span class="i-status" id="nr-form-s"></span></p></form>' +
        "<p>Requests are stored and read by a person. If you run a domain and want it never checked, use the <a href=\"/abuse\">opt-out</a>: an opted-out domain is never listed.</p></details>",
        { ch: "league", right: num(N.count) + " sites" });
      $("#nr-sector").addEventListener("change", function () { setParam("nr", this.value || null); paintNotReady(); });
      $$("#lg-not [data-recheck]").forEach(function (b) {
        b.addEventListener("click", function () {
          var d = b.getAttribute("data-recheck"), st = b.parentNode.querySelector(".i-status");
          b.setAttribute("aria-busy", "true"); status(st, "Checking " + d + " now\u2026");
          getJSON("/api/public/grade/" + enc(d) + "?fresh=1", { cache: "no-store" }).then(function (r) {
            status(st, "Checked " + stamp(r.scanned_at) + ": grade " + r.grade + (r.grade === "A" || r.grade === "B" ? ". It leaves this list." : "."), r.grade === "A" || r.grade === "B" ? "ok" : null);
            if (r.grade === "A" || r.grade === "B") flash(b.closest("li"));
          }).catch(function (e) { status(st, e.message, "bad"); }).finally(function () { b.removeAttribute("aria-busy"); });
        });
      });
      $("#nr-form").addEventListener("submit", function (ev) {
        ev.preventDefault();
        var f = ev.target, st = $("#nr-form-s");
        fetch("/api/public/corrections", { method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json" }, credentials: "omit",
          body: JSON.stringify({ domain: f.domain.value, reason: f.reason.value, contact: f.contact.value }) })
          .then(function (r) { return r.json().then(function (b) { if (!r.ok) throw new Error(b.detail || ("HTTP " + r.status)); return b; }); })
          .then(function () { status(st, "Received. A person will read it.", "ok"); f.reset(); })
          .catch(function (e) { status(st, e.message, "bad"); });
      });
    }).catch(function (e) { box.innerHTML = '<div class="i-empty">' + esc(e.message) + "</div>"; });
  }

  /* Your verified domains: where each stands in its sector (only you see it) and whether it is on
     the public opt-in list. Listing needs an admin; the server refuses anything not verified or
     not graded A or B, and says why. */
  function paintMine() {
    Promise.all([getJSON("/instrument/rank", { auth: token, cache: "no-store" }).catch(function () { return null; }),
                 getJSON("/instrument/pq-ready", { auth: token, cache: "no-store" }).catch(function () { return null; }),
                 getJSON("/instrument/replies", { auth: token, cache: "no-store" }).catch(function () { return null; })]).then(function (r) {
      var R = r[0], P = r[1];
      MY_REPLIES = (r[2] && r[2].replies) || {};
      if (!R && !P) return;
      var listing = {}; ((P && P.domains) || []).forEach(function (x) { listing[x.domain] = x; });
      var rows = ((R && R.domains) || []).map(function (x) {
        var where = x.grade && x.compared_with ? "better than " + pct(x.worse / x.compared_with) + " of " + num(x.compared_with) + " graded " + (x.sector === "unclassified" ? "sites" : x.sector_name + " sites") : x.grade ? "no graded sites to compare with" : 'not graded yet: <a href="/' + esc(x.domain) + '">grade it</a>';
        var L = listing[x.domain] || {};
        var state = L.listed ? '<span class="v-ok">on the public list since ' + esc(day(L.joined_at)) + '</span> <button type="button" class="i-btn" data-list="0" data-d="' + esc(x.domain) + '">Leave the list</button>'
          : (L.eligible ? '<button type="button" class="i-btn" data-list="1" data-d="' + esc(x.domain) + '">List as post-quantum ready</button>' : '<span class="i-dim">listing needs grade A or B</span>') +
            (L.removed_reason ? '<br><span class="v-warn">' + esc(L.removed_reason) + "</span>" : "");
        var rep = (MY_REPLIES || {})[x.domain];
        var reply = '<br><details class="i-fine"><summary>' + (rep ? "Your reply, " + esc(day(rep.at)) : "Reply on the public lists") + '</summary><textarea class="i-btn" maxlength="280" rows="2" data-reply="' + esc(x.domain) + '">' + esc(rep ? rep.text : "") +
          '</textarea><button type="button" class="i-btn" data-reply-save="' + esc(x.domain) + '">Save reply</button>' + (rep ? ' <button type="button" class="i-btn" data-reply-del="' + esc(x.domain) + '">Remove</button>' : "") + "<br>Plain text, at most 280 characters, shown with the date beside this domain if it is listed.</details>";
        return "<tr><td>" + gradeChip(x.grade) + "</td><td>" + esc(x.domain) + "</td><td>" + where + "</td><td>" + state + reply + "</td></tr>";
      }).join("");
      $("#lg-mine").innerHTML = panel("", "Your verified domains (only you see this)", (R && R.verified_domains) ? '<div class="i-table-wrap"><table class="i-table"><tbody>' + rows + '</tbody></table></div><p class="i-status" id="lg-mine-s"></p>'
        : '<p>Verify a domain you own in the console (<a href="/ui/#gateway">Website Gateway</a>) to see where it stands in its sector, and to list it as post-quantum ready.</p>', { ch: "grade" });
      $$("#lg-mine [data-list]").forEach(function (btn) {
        btn.addEventListener("click", function () {
          var d = btn.getAttribute("data-d"), on = btn.getAttribute("data-list") === "1";
          btn.setAttribute("aria-busy", "true");
          var headers = { "Content-Type": "application/json", Accept: "application/json" };
          if (token) headers.Authorization = "Bearer " + token;
          fetch("/instrument/pq-ready/" + enc(d), { method: "PUT", credentials: "same-origin", headers: headers, body: JSON.stringify({ listed: on }) })
            .then(function (res) { return res.json().then(function (b) { if (!res.ok) throw new Error(b.detail || ("HTTP " + res.status)); return b; }); })
            .then(function () { paintMine(); paintReady(); })
            .catch(function (e) { status($("#lg-mine-s"), e.message, "bad"); btn.removeAttribute("aria-busy"); });
        });
      });
      function send(method, d, body) {
        var headers = { "Content-Type": "application/json", Accept: "application/json" };
        if (token) headers.Authorization = "Bearer " + token;
        return fetch("/instrument/replies/" + enc(d), { method: method, credentials: "same-origin", headers: headers, body: body ? JSON.stringify(body) : undefined })
          .then(function (res) { return res.json().then(function (b) { if (!res.ok) throw new Error(b.detail || ("HTTP " + res.status)); return b; }); })
          .then(function () { paintMine(); paintNotReady(); })
          .catch(function (e) { status($("#lg-mine-s"), e.message, "bad"); });
      }
      $$("#lg-mine [data-reply-save]").forEach(function (b) { b.addEventListener("click", function () { var d = b.getAttribute("data-reply-save"); send("PUT", d, { text: $('#lg-mine [data-reply="' + d + '"]').value }); }); });
      $$("#lg-mine [data-reply-del]").forEach(function (b) { b.addEventListener("click", function () { send("DELETE", b.getAttribute("data-reply-del")); }); });
    });
  }
  var MY_REPLIES = {};
  function paintReady() {
    var box = $("#lg-ready"); if (!box) return;
    var order = param("order") === "joined" ? "joined" : "name";
    getJSON("/api/public/pq-ready?order=" + order, { cache: "no-store" }).then(function (Q) {
      var rows = (Q.entries || []).map(function (e) {
        return '<tr><td><a href="/' + esc(e.domain) + '">' + esc(e.domain) + "</a></td><td>" + esc(e.sector_name) + "</td><td>" + gradeChip(e.grade) + '</td><td class="mono">' + esc(day(e.checked_at)) + '</td><td class="mono i-dim">' + esc(day(e.joined_at)) + "</td></tr>";
      }).join("");
      box.innerHTML = panel("", "Post-quantum ready, by choice", (rows ? '<div class="i-table-wrap"><table class="i-table"><thead><tr><th>Domain</th><th>Sector</th><th>Grade</th><th>Checked</th><th>Listed since</th></tr></thead><tbody>' + rows + "</tbody></table></div>"
          : '<p class="i-empty">No organisation has listed itself yet.</p>') +
        '<p class="i-fine">' + esc(Q.about || "") + ' Ordered ' + (order === "name" ? 'by name; <a href="?order=joined">by date listed</a>' : 'by date listed; <a href="/league">by name</a>') + '. <a href="/api/public/pq-ready.atom">Feed</a>.</p>',
        { ch: "grade", right: num(Q.count) + " listed" });
    }).catch(function (e) { box.innerHTML = '<div class="i-empty">' + esc(e.message) + "</div>"; });
  }

  /* A cell's label: the host without its group's domain and port, cut to fit the cell. */
  function shortLabel(id, group) {
    var t = String(id).replace(/:\d+$/, "");
    if (group && t.length > group.length && t.slice(-group.length - 1) === "." + group) t = t.slice(0, -group.length - 1);
    return t.length > 11 ? t.slice(0, 10) + "…" : t;
  }
  function drawAtlas(wrap, groups) {
    var NS = "http://www.w3.org/2000/svg", GAP = 8, CELL = 10;
    var blocks = groups.map(function (g) { var n = Math.max(1, Math.ceil(Math.sqrt(g.cells.length))); return { g: g, n: n, size: n * CELL }; });
    // Shelf-pack the regions into rows of roughly square overall shape.
    var total = blocks.reduce(function (s, b) { return s + (b.size + GAP * 3) * (b.size + GAP * 5); }, 0);
    var W = Math.max(200, Math.sqrt(total) * 1.6), x = 0, y = 0, rowH = 0;
    blocks.forEach(function (b) { var w = b.size + GAP * 2; if (x + w > W && x > 0) { x = 0; y += rowH + GAP * 4; rowH = 0; } b.x = x + GAP; b.y = y + GAP * 3; x += w + GAP; rowH = Math.max(rowH, b.size + GAP * 2); });
    var H = y + rowH + GAP * 4;
    var svg = document.createElementNS(NS, "svg");
    svg.setAttribute("class", "atlas"); svg.setAttribute("role", "img"); svg.setAttribute("aria-label", "Atlas of graded sites by sector");
    var html = "";
    blocks.forEach(function (b) {
      html += '<g class="atlas-region" data-region="' + esc(b.g.id) + '"><rect class="atlas-frame" x="' + (b.x - 3) + '" y="' + (b.y - 3) + '" width="' + (b.size + 6) + '" height="' + (b.size + 6) + '"></rect>' +
        '<text class="atlas-region-label" x="' + (b.x - 3) + '" y="' + (b.y - 7) + '">' + esc(b.g.name) + " (" + b.g.cells.length + ")</text>";
      b.g.cells.forEach(function (c, i) {
        var cx = b.x + (i % b.n) * CELL, cy = b.y + Math.floor(i / b.n) * CELL;
        html += '<a href="' + esc(c.href) + '" class="atlas-cell" data-id="' + esc(c.id) + '"><title>' + esc(c.label + (c.g ? " — grade " + c.g : " — not graded")) + '</title><rect x="' + (cx + .8) + '" y="' + (cy + .8) + '" width="' + (CELL - 1.6) + '" height="' + (CELL - 1.6) + '" data-g="' + esc(c.g || "") + '"></rect>' +
          '<text class="atlas-cell-label" x="' + (cx + 1.2) + '" y="' + (cy + CELL / 2 + .9) + '">' + esc(shortLabel(c.id, b.g.id)) + "</text></a>";
      });
      html += "</g>";
    });
    svg.innerHTML = html;
    wrap.innerHTML = ""; wrap.appendChild(svg);
    var full = { x: 0, y: 0, w: W + GAP, h: H };
    var v = Object.assign({}, full);
    var initial = (param("v") || "").split(",").map(Number);
    if (initial.length === 3 && initial.every(isFinite) && initial[2] > 0) { v = { x: initial[0], y: initial[1], w: initial[2], h: initial[2] * full.h / full.w }; }
    var focus = param("focus");
    if (focus) {
      var el = svg.querySelector('[data-id="' + (window.CSS && CSS.escape ? CSS.escape(focus) : focus) + '"] rect');
      if (el) { var fx = +el.getAttribute("x"), fy = +el.getAttribute("y"); v = { x: fx - 40, y: fy - 40 * full.h / full.w, w: 80, h: 80 * full.h / full.w }; el.parentNode.classList.add("atlas-focus"); }
    }
    var saveT = null;
    function apply() {
      svg.setAttribute("viewBox", v.x + " " + v.y + " " + v.w + " " + v.h);
      var k = full.w / v.w;
      svg.setAttribute("data-zoom", k > 3 ? "near" : k > 1.6 ? "mid" : "far");
      clearTimeout(saveT); saveT = setTimeout(function () { setParam("v", k > 1.01 ? [Math.round(v.x), Math.round(v.y), Math.round(v.w)].join(",") : null); }, 300);
    }
    function zoomAt(f, px, py) {
      var nw = Math.max(30, Math.min(full.w * 1.2, v.w / f)); var nh = nw * full.h / full.w;
      v = { x: px - (px - v.x) * nw / v.w, y: py - (py - v.y) * nh / v.h, w: nw, h: nh }; apply();
    }
    function toSvg(cx, cy) { var r = svg.getBoundingClientRect(); return { x: v.x + (cx - r.left) / r.width * v.w, y: v.y + (cy - r.top) / r.height * v.h }; }
    svg.addEventListener("wheel", function (e) { e.preventDefault(); var p = toSvg(e.clientX, e.clientY); zoomAt(e.deltaY < 0 ? 1.25 : 0.8, p.x, p.y); }, { passive: false });
    var ptrs = {}, drag = null, moved = false, pinch = null;
    svg.addEventListener("pointerdown", function (e) { ptrs[e.pointerId] = { x: e.clientX, y: e.clientY }; moved = false; drag = { x: e.clientX, y: e.clientY, v: Object.assign({}, v) }; if (Object.keys(ptrs).length === 2) { var p = Object.values(ptrs); pinch = { d: Math.hypot(p[0].x - p[1].x, p[0].y - p[1].y), v: Object.assign({}, v) }; } });
    svg.addEventListener("pointermove", function (e) {
      if (!ptrs[e.pointerId]) return; ptrs[e.pointerId] = { x: e.clientX, y: e.clientY };
      var list = Object.values(ptrs);
      if (pinch && list.length === 2) { var d = Math.hypot(list[0].x - list[1].x, list[0].y - list[1].y); var mid = toSvg((list[0].x + list[1].x) / 2, (list[0].y + list[1].y) / 2); v = Object.assign({}, pinch.v); zoomAt(d / pinch.d, mid.x, mid.y); moved = true; return; }
      if (!drag) return; var r = svg.getBoundingClientRect(); var dx = (e.clientX - drag.x) / r.width * v.w, dy = (e.clientY - drag.y) / r.height * v.h;
      if (Math.abs(e.clientX - drag.x) + Math.abs(e.clientY - drag.y) > 4) { moved = true; svg.setPointerCapture(e.pointerId); }
      if (moved) { v.x = drag.v.x - dx; v.y = drag.v.y - dy; apply(); }
    });
    var up = function (e) { delete ptrs[e.pointerId]; if (Object.keys(ptrs).length < 2) pinch = null; if (!Object.keys(ptrs).length) drag = null; };
    svg.addEventListener("pointerup", up); svg.addEventListener("pointercancel", up);
    svg.addEventListener("click", function (e) {
      if (moved) { e.preventDefault(); return; }
      var k = full.w / v.w, a = e.target.closest("a.atlas-cell");
      if (a && k > 3) return; // names are showing: follow the link
      e.preventDefault();
      var reg = e.target.closest(".atlas-region"); if (!reg) return;
      var fr = reg.querySelector(".atlas-frame"), bx = +fr.getAttribute("x"), by = +fr.getAttribute("y"), bw = +fr.getAttribute("width");
      if (a && k > 1.6) { var r2 = a.querySelector("rect"); var cx = +r2.getAttribute("x"), cy = +r2.getAttribute("y"); v = { x: cx - 40, y: cy - 40 * full.h / full.w, w: 80, h: 80 * full.h / full.w }; }
      else { var w = Math.max(bw + 30, 60); v = { x: bx - 15, y: by - 25, w: w, h: w * full.h / full.w }; }
      $("#at-scope").textContent = reg.querySelector(".atlas-region-label").textContent;
      apply();
    });
    svg.tabIndex = 0;
    svg.addEventListener("keydown", function (e) {
      var c = { x: v.x + v.w / 2, y: v.y + v.h / 2 };
      if (e.key === "+" || e.key === "=") zoomAt(1.25, c.x, c.y); else if (e.key === "-") zoomAt(0.8, c.x, c.y);
      else if (e.key === "0") { v = Object.assign({}, full); $("#at-scope").textContent = "all sectors"; apply(); }
      else if (/^Arrow/.test(e.key)) { e.preventDefault(); var s = v.w * .1; if (e.key === "ArrowLeft") v.x -= s; if (e.key === "ArrowRight") v.x += s; if (e.key === "ArrowUp") v.y -= s; if (e.key === "ArrowDown") v.y += s; apply(); }
    });
    apply();
  }

  /* Algorithms: the reference and the internet's cryptography, dated. */
  function riskTone(r) { return r === "broken" ? "v-bad" : r === "weakened" ? "v-warn" : "v-ok"; }
  function viewAlgorithms() {
    var ref = window.MORROW_REF;
    setView("ref", "Algorithms");
    var fam = param("family") || "";
    var list = ref.algorithms.filter(function (a) { return !fam || a.family === fam; });
    var broken = ref.algorithms.filter(function (a) { return a.risk === "broken"; }).length;
    say(byDepth({ plain: broken + " of the " + ref.algorithms.length + " algorithms here would be broken by a large quantum computer; the post-quantum ones are their replacements.",
      standard: ref.algorithms.length + " algorithms: what each one is, whether a quantum computer breaks it, and when the internet started and stopped using it.",
      expert: "Sizes from the cited FIPS/RFCs; risk per Shor (public-key) and Grover (symmetric); dates from primary sources." }));
    var fams = ["Post-quantum", "Hybrid", "Classical", "Symmetric"];
    main.innerHTML =
      '<nav class="i-channels" aria-label="Family"><a href="/algorithms"' + (!fam ? ' aria-current="page"' : "") + ">All</a>" + fams.map(function (f) { return '<a href="/algorithms?family=' + enc(f) + '"' + (fam === f ? ' aria-current="page"' : "") + ">" + f + "</a>"; }).join("") + "</nav>" +
      panel("", "The algorithms", '<div class="i-table-wrap"><table class="i-table"><thead><tr><th>Name</th><th>What it does</th><th>Against a quantum computer</th></tr></thead><tbody>' +
        list.map(function (a) { return '<tr><td><a href="/algorithms/' + a.id + '">' + esc(a.name) + "</a></td><td>" + esc(a.kind) + '</td><td class="' + riskTone(a.risk) + '">' + esc(ref.riskLabel[a.risk]) + "</td></tr>"; }).join("") + "</tbody></table></div>", { ch: "ref" });
  }
  function timeline(events) {
    var ref = window.MORROW_REF;
    return '<ol class="i-tl">' + events.map(function (h) {
      return '<li><span class="y">' + h.y + "</span> " + esc(h.d) + (h.a.length && depth !== "plain" ? ' <span class="i-fine">' + h.a.map(function (id) { var a = ref.get(id); return a ? '<a href="/algorithms/' + id + '">' + esc(a.name) + "</a>" : ""; }).join(", ") + "</span>" : "") +
        (depth === "expert" ? '<br><a class="i-fine" href="' + esc(h.src.href) + '" rel="noopener">' + esc(h.src.label) + "</a>" : "") + "</li>";
    }).join("") + '<li><span class="y">' + new Date().getUTCFullYear() + '</span> Now. <a href="/league">How far the web has got</a>.</li></ol>' + (depth !== "expert" ? '<p class="i-fine">Turn the dial to expert for each event\'s source.</p>' : "");
  }
  function viewAlgorithm(id) {
    var ref = window.MORROW_REF, a = ref.get(id) || ref.find(id);
    if (!a) { setView("ref", "Not found"); say("Morrow has no reference page for “" + id + "”."); main.innerHTML = '<p><a href="/algorithms">All algorithms</a></p>'; return; }
    if (a.id !== id) { location.replace("/algorithms/" + a.id + location.search); return; }
    setView("ref", a.name);
    remember("algorithm", a.id, a.name);
    say(byDepth({ plain: a.name + ": " + (a.risk === "broken" ? "a future quantum computer breaks it." : a.risk === "weakened" ? "a quantum computer weakens it a little; it stays safe to use." : "built to stay safe against quantum computers."), standard: a.summary, expert: a.riskText }));
    var events = ref.history.filter(function (h) { return h.a.indexOf(a.id) >= 0; });
    main.innerHTML = '<p class="i-eyebrow">' + esc(a.family) + " &middot; " + esc(a.kind) + '</p><h1 class="i-h1">' + esc(a.name) + "</h1>" +
      (a.aka.length ? '<p class="i-fine">Also written ' + a.aka.map(esc).join(", ") + "</p>" : "") +
      '<div class="ch-grid"><div class="span-8">' +
      panel("", "Against a quantum computer", '<p class="' + riskTone(a.risk) + '"><b>' + esc(ref.riskLabel[a.risk]) + "</b></p><p>" + esc(depth === "plain" ? a.summary : a.riskText) + "</p><p class=\"i-fine\">Status: " + esc(a.status) + "</p>", { ch: "ref" }) +
      (a.params && depth !== "plain" ? panel("", "Sizes (bytes unless stated)", '<div class="i-table-wrap"><table class="i-table"><thead><tr>' + a.params.cols.map(function (c) { return "<th>" + esc(c) + "</th>"; }).join("") + "</tr></thead><tbody>" + a.params.rows.map(function (r) { return "<tr>" + r.map(function (c) { return "<td>" + esc(c) + "</td>"; }).join("") + "</tr>"; }).join("") + "</tbody></table></div>", { ch: "ref" }) : "") +
      (a.seenIn ? panel("", "Where you meet it", "<p>" + esc(a.seenIn) + "</p>", { ch: "ref" }) : "") +
      "</div><div class=\"span-4\">" +
      (events.length ? panel("", "Its history", timeline(events), { ch: "ref" }) : "") +
      panel("", "Related", "<ul>" + a.related.map(function (r) { var x = ref.get(r); return x ? '<li><a href="/algorithms/' + r + '">' + esc(x.name) + "</a></li>" : ""; }).join("") + "</ul>", { ch: "ref" }) +
      panel("", "Sources", "<ul>" + a.sources.map(function (s) { return '<li><a href="' + esc(s.href) + '" rel="noopener">' + esc(s.label) + "</a></li>"; }).join("") + "</ul>", { ch: "ref" }) +
      "</div></div>";
  }

  /* Trust: what this server runs, checked in this browser where a browser can check it. */
  function viewTrust() {
    setView("trust", "Trust");
    say("Checking what this server runs…");
    var asked = (param("commit") || "").toLowerCase();
    main.innerHTML = '' +
      '<div class="ch-grid"><div class="span-6">' + panel("", "Running commit", '<div id="tr-build" class="i-muted">Reading&hellip;</div>', { ch: "trust" }) + "</div>" +
      '<div class="span-6">' + panel("", "The files this page loaded", '<div id="tr-man" class="i-muted">Reading&hellip;</div>', { ch: "trust" }) + "</div>" +
      '<div class="span-12">' + panel("", "Deploy log", '<div id="tr-log" class="i-muted">Reading&hellip;</div>', { ch: "trust" }) + "</div>" +
      '<div class="span-6">' + panel("", "No tracking: what this page contacted", '<div id="tr-req" class="i-muted">Reading&hellip;</div>', { ch: "trust" }) + "</div>" +
      '<div class="span-6">' + panel("", "Rebuild it yourself", '<p>Release images are built reproducibly: two builds of the same commit give the same image digest, and each release image carries a keyless cosign signature and build attestations. The steps are in <a href="https://github.com/soqlab/Morrow/blob/main/docs/REPRODUCIBLE_BUILDS.md" rel="noopener">docs/REPRODUCIBLE_BUILDS.md</a>.</p>' +
        '<p>To check this server from a terminal, with a clone of the repository:</p><pre id="tr-cmd">python scripts/verify-deploy.py --url ' + esc(location.origin) + ' --repo .</pre><button type="button" class="i-btn" id="tr-copy">Copy</button>' +
        '<p class="i-fine">It compares every served file with the commit\'s source, and recomputes the deploy log\'s hash chain.</p>', { ch: "tools" }) + "</div></div>";
    $("#tr-copy").addEventListener("click", function (e) { copy($("#tr-cmd").textContent, e.target); });
    var results = { build: null, files: null, chain: null };
    function summary() {
      var b = results.build;
      if (!b) return;
      var parts = [];
      parts.push(b.commit ? "This server says it runs commit " + b.commit.slice(0, 12) + "." : "This server does not report its commit.");
      if (results.files != null) parts.push(results.files ? "The files this page loaded match the list this server publishes for that commit." : "A file this page loaded does not match the list this server publishes.");
      if (results.chain != null) parts.push(results.chain ? "The deploy log's hash chain recomputes in your browser." : "The deploy log's hash chain does not recompute.");
      say(parts.filter(Boolean).join(" "));
    }
    getJSON("/api/public/build", { cache: "no-store" }).then(function (b) {
      results.build = b;
      var match = asked ? (b.commit && b.commit.indexOf(asked) === 0 ? '<p class="v-ok">Yes: commit ' + esc(asked) + " is the one this server reports.</p>" : '<p class="v-warn">No: this server reports ' + esc(b.commit || "no commit") + ", not " + esc(asked) + ".</p>") : "";
      $("#tr-build").innerHTML = match + (b.commit
        ? '<dl class="readouts">' + reading("Commit", '<a href="' + esc(b.commit_url) + '" rel="noopener">' + esc(b.commit) + "</a>") + reading("Reported by", esc(b.source || "-")) + reading("Process started", esc(stamp(b.started_at))) + reading("Python", esc(b.python || "-")) + "</dl>" +
          '<p class="i-fine">The commit comes from the hosting platform\'s build environment (' + esc(b.source) + '), not from the code itself, so the link above shows exactly the source that was deployed. To check that claim, compare the files with that commit: on the right, or with the script below.</p>'
        : "<p>The server was started without a commit in its environment, so it cannot say which source it runs. Self-hosters: set <code>MORROW_GIT_COMMIT</code>.</p>");
      summary();
    }).catch(function (e) { $("#tr-build").textContent = e.message; });

    getJSON("/api/public/manifest", { cache: "no-store" }).then(function (m) {
      var byPath = {}; (m.files || []).forEach(function (f) { byPath[f.path] = f; });
      var mine = ["/ui/instrument.html", "/ui/instrument.js", "/ui/instrument-data.js", "/ui/instrument.css"];
      return Promise.all(mine.map(function (p) {
        return fetch(p, { cache: "no-store" }).then(function (res) { return res.arrayBuffer(); }).then(sha256Hex).then(function (h) { return { path: p, mine: h, listed: byPath[p] ? byPath[p].sha256 : null }; });
      })).then(function (rows) {
        results.files = rows.every(function (x) { return x.listed && x.listed === x.mine; });
        var html = '<div class="i-table-wrap"><table class="i-table"><thead><tr><th>File</th><th>SHA-256 in your browser</th><th>Matches</th></tr></thead><tbody>' + rows.map(function (x) {
          return '<tr><td class="mono">' + esc(x.path) + '</td><td class="mono"><small>' + esc(x.mine.slice(0, 16)) + "&hellip;</small></td><td class=\"" + (x.listed === x.mine ? "v-ok\">yes" : "v-bad\">no") + "</td></tr>";
        }).join("") + "</tbody></table></div><p class=\"i-fine\">" + num((m.files || []).length) + " files listed for commit " + esc((m.commit || "unknown").slice(0, 12)) + ", generated " + esc(stamp(m.generated_at)) + ".</p>";
        $("#tr-man").innerHTML = html;
        summary();
      });
    }).catch(function (e) { $("#tr-man").textContent = e.message; });

    getJSON("/api/public/deploys?limit=500", { cache: "no-store" }).then(function (L) {
      var entries = (L.entries || []).slice().sort(function (a, b) { return a.seq - b.seq; });
      var prev = L.genesis_hash || "0".repeat(64);
      var check = entries.reduce(function (p, e) {
        return p.then(function (ok) {
          return sha256Hex(new TextEncoder().encode(canonical({ commit: e.commit, first_seen: e.first_seen, prev_hash: e.prev_hash, seq: e.seq }))).then(function (h) {
            var good = ok && e.prev_hash === prev && h === e.entry_hash; prev = e.entry_hash; return good;
          });
        });
      }, Promise.resolve(true));
      return check.then(function (ok) {
        results.chain = entries.length ? ok : null;
        $("#tr-log").innerHTML = !entries.length ? "<p>No deploy has been recorded yet. A deploy is recorded when the server starts on a commit different from the last one.</p>" :
          "<p class=\"" + (ok ? "v-ok" : "v-bad") + "\">" + (ok ? "Chain of " + entries.length + (entries.length === 1 ? " entry" : " entries") + " recomputed in your browser: every entry links to the one before." : "The chain does not recompute: an entry was changed or removed.") + "</p>" +
          '<div class="i-table-wrap"><table class="i-table"><thead><tr><th>#</th><th>Commit</th><th>First seen</th><th>Entry hash</th></tr></thead><tbody>' +
          entries.slice().reverse().slice(0, 50).map(function (e) { return '<tr><td class="num">' + e.seq + '</td><td class="mono"><a href="https://github.com/soqlab/Morrow/commit/' + esc(e.commit) + '" rel="noopener">' + esc(e.commit.slice(0, 12)) + '</a></td><td class="mono">' + esc(stamp(e.first_seen)) + '</td><td class="mono"><small>' + esc(e.entry_hash.slice(0, 16)) + "&hellip;</small></td></tr>"; }).join("") +
          '</tbody></table></div><p class="i-fine">Head hash <code>' + esc(L.head_hash || "") + "</code>. Keep a copy: if the whole log were ever rewritten, the head you saved would no longer be in it.</p>";
        summary();
      });
    }).catch(function (e) { $("#tr-log").textContent = e.message; });

    function requests() {
      var csp = null;
      fetch(location.href, { cache: "no-store" }).then(function (r) { csp = r.headers.get("content-security-policy"); }).catch(function () {}).finally(function () {
        var entries = performance.getEntriesByType("resource").map(function (e) { return e.name; });
        entries.unshift(location.href);
        var origins = {}; entries.forEach(function (u) { try { var o = new URL(u).origin; origins[o] = (origins[o] || 0) + 1; } catch (e) { /* ignore */ } });
        var foreign = Object.keys(origins).filter(function (o) { return o !== location.origin; });
        $("#tr-req").innerHTML = '<p class="' + (foreign.length ? "v-bad\">This page contacted " + foreign.map(esc).join(", ") : "v-ok\">Every one of the " + entries.length + " requests this page has made went to " + esc(location.origin) + ". No analytics, no fonts or scripts from elsewhere, no cookies set by this page.") + "</p>" +
          '<p class="i-fine">Read live from your browser\'s own list of requests (Resource Timing). The policy the server sent with this page forbids anything else:</p><pre>' + esc(csp || "(not readable here)") + "</pre>";
      });
    }
    setTimeout(requests, 1500);
  }

  /* What instrument-watch.js (watch mode, claims, /about-scanner) builds its views with. */
  window.MorrowIns = { $: $, $$: $$, esc: esc, enc: enc, getJSON: getJSON, panel: panel, reading: reading, say: say, setView: setView,
    status: status, stamp: stamp, day: day, ago: ago, copy: copy, flash: flash, byDepth: byDepth, depth: function () { return depth; },
    token: token, workspace: workspace, main: main };

  /* ── start ─────────────────────────────────────────────────────────────── */
  dial();
  paintConnStrip();
  footer();
  var cb = $("#i-cmd-btn"); if (cb) cb.addEventListener("click", openPalette);
  route();
})();
