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
  function b64bytes(s) { var bin = atob(s); var out = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i); return out; }
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
  var PAGES = [
    { t: "Check a domain", h: "/", k: "home grade check domain start", g: "Page" },
    { t: "League of top sites by sector", h: "/league", k: "league table sector ranking banks government", g: "Page" },
    { t: "Atlas: zoom through every graded site", h: "/atlas", k: "atlas map zoom estate space", g: "Page" },
    { t: "Algorithms and their history", h: "/algorithms", k: "algorithms reference history timeline pqc", g: "Page" },
    { t: "What this server runs, and how to check it", h: "/trust", k: "trust commit verify signed manifest deploy log csp tracking reproducible", g: "Page" },
    { t: "Plain version, no scripts", h: "/plain", k: "plain text accessible screen reader no javascript", g: "Page" },
    { t: "Open the console", h: "/ui/", k: "console sign in login estate scans account", g: "Console" },
    { t: "Full certificate-transparency check", h: "/check", k: "check ct certificate transparency deadlines", g: "Page" }
  ];
  function recognize(raw, limit) {
    var q = String(raw || "").trim(); var out = [];
    limit = limit || 10;
    if (!q) {
      recent().forEach(function (r) { out.push({ kind: r.kind, t: r.label, h: r.kind === "domain" ? "/" + r.id : r.kind === "algorithm" ? "/algorithms/" + r.id : r.id, hint: "Looked at " + ago(r.at) }); });
      return out.concat(PAGES.map(function (p) { return { kind: "page", t: p.t, h: p.h, hint: p.g }; })).slice(0, limit);
    }
    var ref = window.MORROW_REF;
    var algo = ref && ref.find(q);
    if (algo) out.push({ kind: "algorithm", t: algo.name, h: "/algorithms/" + algo.id, hint: algo.kind });
    var cve = /^cve-\d{4}-\d{4,}$/i.test(q) ? q.toUpperCase() : null;
    if (cve) out.push({ kind: "cve", t: cve + " in the NVD", h: "https://nvd.nist.gov/vuln/detail/" + cve, hint: "Opens nvd.nist.gov", ext: true });
    var d = !algo && !cve ? asDomain(q) : null;
    if (d) {
      out.push({ kind: "domain", t: "Grade " + d, h: "/" + d, hint: "Is its connection quantum-safe?" });
      out.push({ kind: "domain", t: d + " on the atlas", h: "/atlas?focus=" + enc(d), hint: "Where it sits among the rest" });
    }
    var sha = !d && /^[0-9a-f]{7,40}$/i.test(q) && /\d/.test(q) ? q.toLowerCase() : null;
    if (sha) out.push({ kind: "commit", t: "Commit " + sha.slice(0, 12), h: "/trust?commit=" + sha, hint: "Is it the one this server runs?" });
    var words = q.toLowerCase().split(/\s+/).filter(Boolean);
    var pool = PAGES.map(function (p) { return { kind: "page", t: p.t, h: p.h, hay: (p.t + " " + p.k + " " + p.g).toLowerCase(), hint: p.g }; });
    if (ref) ref.algorithms.forEach(function (a) { pool.push({ kind: "algorithm", t: a.name, h: "/algorithms/" + a.id, hay: [a.name, a.kind, a.family].concat(a.aka).join(" ").toLowerCase(), hint: a.kind }); });
    (SECTORS || []).forEach(function (s) { pool.push({ kind: "page", t: s.name + " in the league", h: "/league?sector=" + enc(s.id), hay: (s.name + " " + s.id + " league sector").toLowerCase(), hint: "Sector" }); });
    pool.filter(function (p) { return words.every(function (w) { return p.hay.indexOf(w) >= 0; }); })
      .forEach(function (p) { if (!out.some(function (o) { return o.h === p.h; })) out.push(p); });
    return out.slice(0, limit);
  }
  var SECTORS = null;

  function optionsHtml(list, sel) {
    if (!list.length) return '<div class="i-empty">Nothing matches. A domain looks like <code>example.com</code>; an algorithm like <code>ML-KEM</code> or <code>secp256r1</code>; a commit is 7 to 40 hex characters.</div>';
    return list.map(function (o, i) {
      return '<a class="i-opt" role="option" id="opt-' + i + '" data-kind="' + esc(o.kind) + '" aria-selected="' + (i === sel) + '" href="' + esc(o.h) + '"' + (o.ext ? ' rel="noopener" target="_blank"' : "") + '>' +
        '<span class="k">' + esc(o.kind) + '</span><span class="t">' + esc(o.t) + '</span><span class="h">' + esc(o.hint || "") + "</span></a>";
    }).join("");
  }
  /* Wire an input to a list of options. Enter opens the selected one. */
  function bindRecognizer(input, listEl, onGo) {
    var sel = 0, view = [];
    function paint() { view = recognize(input.value); sel = Math.min(sel, Math.max(0, view.length - 1)); listEl.innerHTML = optionsHtml(view, sel); input.setAttribute("aria-activedescendant", view.length ? "opt-" + sel : ""); }
    input.addEventListener("input", function () { sel = 0; paint(); });
    input.addEventListener("keydown", function (e) {
      if (e.key === "ArrowDown") { e.preventDefault(); sel = (sel + 1) % Math.max(1, view.length); paint(); }
      else if (e.key === "ArrowUp") { e.preventDefault(); sel = (sel - 1 + view.length) % Math.max(1, view.length); paint(); }
      else if (e.key === "Enter") { e.preventDefault(); if (view[sel]) { if (onGo) onGo(); go(view[sel]); } }
    });
    paint();
    return paint;
  }
  function go(o) { if (o.ext) window.open(o.h, "_blank", "noopener"); else location.href = o.h; }

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
      var label = c.status === "pq" ? "post-quantum" : c.status === "classical" ? "classical" : "not reported";
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
  function say(text) { var el = $("#say"); if (el) el.textContent = text; }
  function setView(channel, title) {
    document.title = title ? title + " · Morrow" : "Morrow";
    document.body.setAttribute("data-ch", channel);
    $$(".i-channels a").forEach(function (a) { if (a.getAttribute("data-view") === channel) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current"); });
  }
  function status(el, text, tone) { if (!el) return; el.textContent = text || ""; if (tone) el.setAttribute("data-tone", tone); else el.removeAttribute("data-tone"); }
  function panel(n, title, body, extra) {
    return '<section class="ch"' + (extra && extra.ch ? ' data-ch="' + extra.ch + '"' : "") + (extra && extra.id ? ' id="' + extra.id + '"' : "") + '><div class="ch-head"><span class="ch-n">' + esc(n) + "</span><span>" + esc(title) + "</span>" +
      (extra && extra.right ? '<span class="ch-r">' + extra.right + "</span>" : "") + '</div><div class="ch-body">' + body + "</div></section>";
  }
  function reading(k, v, cls) { return '<div class="reading"><dt>' + esc(k) + '</dt><dd class="' + (cls || "") + '">' + v + "</dd></div>"; }
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

  /* ── views ─────────────────────────────────────────────────────────────── */
  var segs = location.pathname.replace(/\/+$/, "").split("/").filter(Boolean).map(decodeURIComponent);
  function route() {
    var s0 = segs[0] || "";
    if (!s0) return viewHome();
    if (s0 === "league") return viewLeague();
    if (s0 === "atlas") return viewAtlas();
    if (s0 === "algorithms") return segs[1] ? viewAlgorithm(segs[1]) : viewAlgorithms();
    if (s0 === "trust") return viewTrust();
    var d = asDomain(s0);
    if (d && segs.length === 1) return viewDomain(d);
    setView("grade", "Not found");
    say("There is nothing at this address.");
    main.innerHTML = panel("404", "Not here", '<p>Type what you were looking for instead: <a href="/">check a domain</a>, <a href="/league">the league</a>, <a href="/algorithms">algorithms</a>.</p>');
  }

  /* Home: the one input, your own connection, and live counts. */
  function viewHome() {
    setView("grade", "Is it quantum-safe?");
    var last = recent()[0];
    say(byDepth({ plain: "Type a website's address and Morrow tells you whether traffic to it could be read by a future quantum computer, and how to fix it.",
      standard: "Type a domain, an algorithm, a CVE or a commit. A domain gets its grade, the year recorded traffic could be read, and the fix.",
      expert: "One input, recognised: hostname → grade (rubric on /api/public), algorithm → reference, CVE → NVD, hex → commit check." }));
    main.innerHTML =
      '<div class="ch-grid">' +
      '<div class="span-7">' + panel("CH1", "Check", '<label class="sr-only" for="home-q">Domain, algorithm, CVE or commit</label>' +
        '<div class="i-field"><span class="p" aria-hidden="true">&rsaquo;</span><input id="home-q" type="text" autocomplete="off" spellcheck="false" inputmode="url" role="combobox" aria-expanded="true" aria-controls="home-l" placeholder="example.com"></div>' +
        '<div class="i-opts" id="home-l" role="listbox"></div>' +
        (last ? '<p class="i-fine">Last time you looked at <a href="' + esc(last.kind === "domain" ? "/" + last.id : last.kind === "algorithm" ? "/algorithms/" + last.id : last.id) + '">' + esc(last.label) + "</a>, " + esc(ago(last.at)) + ". Kept on this device only.</p>" : "") +
        '<p class="i-fine">The address works too: <code>' + esc(location.host) + '/example.com</code>.</p>', { ch: "grade" }) + "</div>" +
      '<div class="span-5">' + panel("CH2", "Your connection", '<p id="home-conn" class="i-muted">Reading your connection&hellip;</p><dl class="readouts" id="home-conn-r"></dl>', { ch: "conn" }) +
        (token ? panel("CH3", "Signed in", '<p>You are signed in on this device. Your own estate is in the <a href="/ui/">console</a> and on the <a href="/atlas">atlas</a>.</p>', { ch: "atlas" }) : "") + "</div>" +
      '<div class="span-12">' + panel("CH4", "Checked on this server", '<dl class="readouts" id="home-stats"></dl><p class="i-fine" id="home-stats-n"></p>', { ch: "league", right: '<a href="/league">league</a>' }) + "</div>" +
      "</div>";
    bindRecognizer($("#home-q"), $("#home-l"));
    $("#home-q").focus();
    Promise.all([connection(), basis()]).then(function (r) {
      var c = r[0];
      $("#home-conn").textContent = connSentence(c, r[1]);
      if (c.kex) $("#home-conn-r").innerHTML = reading("Key exchange", esc(c.kex), c.status === "pq" ? "v-ok" : "v-warn") + reading("Protocol", esc(c.tls || "-")) + reading("HTTP", esc(c.http || "-"));
    });
    getJSON("/api/public/stats").then(function (s) {
      var g = s.grades_7d || {};
      $("#home-stats").innerHTML = reading("Checks, all time", num(s.public_checks_total)) + reading("Checks, last 7 days", num(s.public_checks_7d)) +
        reading("Domains checked", num(s.domains_checked)) + reading("Post-quantum, 7 days", pct(s.pq_share_7d), "v-ok") +
        ["A", "B", "C", "D", "E", "F"].map(function (k) { return reading("Grade " + k + ", 7 days", '<span class="g-chip" data-g="' + k + '">' + num(g[k] || 0) + "</span>"); }).join("");
      $("#home-stats-n").textContent = "Counted from this server's stored results, read at " + stamp(s.generated_at) + ". Rubric " + s.rubric_version + ".";
    }).catch(function (e) { $("#home-stats").innerHTML = '<div class="i-empty">The counts are not available: ' + esc(e.message) + "</div>"; });
  }

  /* A domain: grade, decrypt year, fix, re-check, history scrubbed through time, badge. */
  function viewDomain(d) {
    setView("grade", d);
    remember("domain", d, d);
    say("Checking " + d + "…");
    main.innerHTML = '<p class="i-eyebrow">Domain</p><div class="i-row"><h1 class="i-h1">' + esc(d) + '</h1></div><p class="i-status" id="d-status" role="status" aria-live="polite">Asking Morrow\'s server to check ' + esc(d) + '. A first check opens a few TLS connections to port 443 and takes up to half a minute.</p><div id="d-body"></div>';
    var history_ = [], current = null, latest = null;
    var at = param("at");

    function load(fresh) {
      var st = $("#d-status");
      status(st, fresh ? "Re-checking " + d + " now…" : st.textContent);
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
              if (fresh) {
                var changed = before && before.grade !== r.grade;
                status($("#d-status"), changed ? "Grade changed from " + before.grade + " to " + r.grade + " on this re-check." : "Re-checked " + stamp(r.scanned_at) + ": same grade, " + r.grade + ".", changed ? "ok" : null);
                var g = $("#d-grade"); if (g) { g.classList.remove("flash"); void g.offsetWidth; g.classList.add("flash"); }
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

    function render() {
      var r = current, isLatest = r === latest || (latest && r.scanned_at === latest.scanned_at);
      var kx = r.key_exchange || {}, tls = r.tls || {}, cert = r.certificate || {}, ex = r.exposure || {}, sm = r.summaries || {};
      say(byDepth({ plain: sm.executive || r.summary, standard: r.summary, expert: sm.cryptographer || sm.engineer || r.summary }));
      if (isLatest) status($("#d-status"), "Checked " + stamp(r.scanned_at) + (r.cached ? " (stored result, " + ago(r.scanned_at) + ")" : "") + ", rubric " + r.rubric_version + ".");
      else status($("#d-status"), "Showing the check of " + stamp(r.scanned_at) + ". The newest is " + stamp(latest.scanned_at) + ".");
      var vers = ["1.3", "1.2", "1.1", "1.0"].filter(function (v) { return (tls.versions || {})[v]; });
      var readings =
        reading("Key exchange", esc(kx.group || "not observed"), kx.post_quantum ? "v-ok" : "v-warn") +
        reading("Post-quantum", kx.post_quantum ? "yes" : "no", kx.post_quantum ? "v-ok" : "v-warn") +
        reading("Protocol", esc(tls.negotiated || "-"));
      if (depth !== "plain") readings += reading("Versions accepted", esc(vers.join(", ") || "-"), (tls.versions || {})["1.0"] || (tls.versions || {})["1.1"] ? "v-warn" : "") +
        reading("Forward secrecy", r.forward_secrecy ? "yes" : "no", r.forward_secrecy ? "" : "v-bad") +
        reading("Certificate", esc((cert.key_type || "-") + " " + (cert.key_bits || "")) + "<br><small>expires " + esc(day(cert.not_after)) + "</small>", cert.verified === false ? "v-bad" : "") +
        reading("Served by", esc(r.server_software || r.platform || "not disclosed"));
      if (depth === "expert") readings += reading("PQ groups accepted", esc((kx.offered_pq_groups_accepted || []).join(", ") || "none")) +
        reading("Signature", esc(cert.signature_algorithm || "-")) + reading("Issuer", "<small>" + esc(cert.issuer || "-") + "</small>") + reading("Connections opened", num(r.connections));

      var exposure = ex.recorded_traffic_at_risk && ex.decrypt_year_low
        ? '<p class="i-big v-warn">' + esc(ex.decrypt_year_low) + "–" + esc(ex.decrypt_year_high) + "</p><p>" + esc(byDepth({
            plain: "Someone recording traffic to " + d + " today could read it from about then.",
            standard: "Traffic recorded today could be decrypted from about " + ex.decrypt_year_low + ", likely by " + ex.decrypt_year_high + ".",
            expert: ex.basis })) + "</p>"
        : ex.recorded_traffic_at_risk
          ? "<p>" + esc(ex.basis || "No encryption was negotiated.") + "</p>"
          : '<p class="i-big v-ok">Not by a quantum computer</p><p>' + esc(depth === "plain" ? "The key exchange already includes post-quantum protection." : ex.basis) + "</p>";
      exposure += '<p class="i-fine">Source: <a href="' + esc(ex.source_url) + '" rel="noopener">' + esc(ex.source_url) + "</a></p>";
      if (ex.recorded_traffic_at_risk && ex.decrypt_year_low) {
        exposure += '<div class="i-row"><label for="d-life">What is sent here must stay secret for</label><select id="d-life" class="i-btn">' +
          [[1, "1 year"], [5, "5 years"], [10, "10 years (most records)"], [25, "25 years (health, state secrets)"]].map(function (o) { return '<option value="' + o[0] + '"' + (String(o[0]) === (param("life") || "10") ? " selected" : "") + ">" + o[1] + "</option>"; }).join("") +
          '</select></div><p id="d-life-out"></p>';
      }

      var fixes = r.fixes || [];
      var fixHtml = fixes.length ? fixes.map(function (f, i) {
        return '<div class="ch" data-ch="tools"><div class="ch-head"><span>' + esc(f.title) + '</span><span class="ch-r"><button type="button" class="i-btn" data-copy="' + i + '">Copy</button></span></div><div class="ch-body"><pre>' + esc(f.snippet) + "</pre>" +
          (depth !== "plain" && f.notes ? '<p class="i-fine">' + esc(f.notes) + "</p>" : "") + '<p class="i-fine">Needs: ' + esc(f.requires) + "</p></div></div>";
      }).join("") : '<p>Nothing to change. ' + (r.grade === "A" ? "This is the top grade." : "") + "</p>";
      if (fixes.length > 1 && r.platform === "unknown") fixHtml = '<p class="i-fine">The server software is not disclosed, so here is the change for each common server. Use the one you run.</p>' + fixHtml;

      var reasons = (r.reasons || []).map(function (x) { return "<li>" + esc(x) + "</li>"; }).join("");
      var origin = location.origin;
      var badgeMd = "[![quantum-ready](" + origin + "/api/public/badge/" + d + ".svg)](" + origin + "/" + d + ")";
      var badgeHtml = '<a href="' + origin + "/" + d + '"><img src="' + origin + "/api/public/badge/" + d + '.svg" alt="quantum-ready grade for ' + d + '"></a>';

      $("#d-body").innerHTML =
        '<div class="ch-grid">' +
        '<div class="span-8">' + panel("CH1", "Grade", '<div class="i-row"><div class="grade" id="d-grade" data-g="' + esc(r.grade) + '" aria-label="Grade ' + esc(r.grade) + '">' + esc(r.grade) + '</div><div><ul class="i-muted">' + reasons + '</ul></div></div><dl class="readouts">' + readings + "</dl>", { ch: "grade" }) + "</div>" +
        '<div class="span-4">' + panel("CH2", "Recorded today, readable from", exposure, { ch: "conn" }) + "</div>" +
        '<div class="span-12">' + panel("CH3", "Through time", '<div class="scrub" id="d-scrub" role="listbox" aria-label="Checks of ' + esc(d) + ', oldest to newest. Scroll or use the arrow keys to move through time." tabindex="0"></div><p class="i-fine" id="d-scrub-n"></p>',
          { ch: "league", right: '<a href="/api/public/history/' + enc(d) + '.atom">feed of grade changes</a>' }) + "</div>" +
        '<div class="span-8">' + panel("CH4", "The fix for this setup", fixHtml + '<div class="i-row"><button type="button" class="i-btn solid" id="d-recheck">Re-check now</button><span class="i-fine">After changing the config, re-check: Morrow opens fresh connections instead of using the stored result.</span></div>', { ch: "tools" }) + "</div>" +
        '<div class="span-4">' + panel("CH5", "Badge", '<p><img src="/api/public/badge/' + enc(d) + '.svg" alt="quantum-ready grade badge for ' + esc(d) + '"></p>' +
          '<p class="i-fine">For a README (Markdown):</p><pre id="d-md">' + esc(badgeMd) + '</pre><button type="button" class="i-btn" data-copy-el="d-md">Copy</button>' +
          '<p class="i-fine">For a web page (HTML):</p><pre id="d-html">' + esc(badgeHtml) + '</pre><button type="button" class="i-btn" data-copy-el="d-html">Copy</button>' +
          '<p class="i-fine">The badge shows the newest stored grade and is cached for up to three hours.</p>', { ch: "grade" }) +
          panel("CH6", "Elsewhere", '<ul><li><a href="/check/' + enc(d) + '">Full check with certificate-transparency history</a></li><li><a href="/plain/' + enc(d) + '">Plain version</a></li><li><a href="/api/public/grade/' + enc(d) + '.txt">As text, for curl</a></li><li><a href="/api/public/grade/' + enc(d) + '">As JSON</a></li><li><a href="/atlas?focus=' + enc(d) + '">On the atlas</a></li></ul>', { ch: "ref" }) + "</div>" +
        "</div>";

      $$("[data-copy]").forEach(function (b) { b.addEventListener("click", function () { copy(fixes[+b.getAttribute("data-copy")].snippet, b); }); });
      $$("[data-copy-el]").forEach(function (b) { b.addEventListener("click", function () { copy($("#" + b.getAttribute("data-copy-el")).textContent, b); }); });
      $("#d-recheck").addEventListener("click", function () { load(true); });
      var life = $("#d-life");
      function lifeOut() {
        var n = +life.value, until = new Date().getUTCFullYear() + n, low = ex.decrypt_year_low;
        setParam("life", n === 10 ? null : String(n));
        $("#d-life-out").textContent = until >= low
          ? "Secret until " + until + ". Recordings could be readable from about " + low + ": up to " + (until - low) + " year" + (until - low === 1 ? "" : "s") + " of exposure, unless the key exchange changes before the traffic is recorded."
          : "Secret until " + until + ", before the earliest estimate of " + low + ". Recordings made today are likely to outlive their value.";
      }
      if (life) { life.addEventListener("change", lifeOut); lifeOut(); }
      paintScrub();
    }

    function paintScrub() {
      var box = $("#d-scrub"); if (!box) return;
      box.innerHTML = history_.map(function (h, i) {
        return '<button type="button" role="option" data-i="' + i + '" data-g="' + esc(h.grade) + '" aria-current="' + (h.result === current || h.scanned_at === current.scanned_at) + '" title="' + esc(stamp(h.scanned_at) + ": " + h.grade) + '" aria-label="' + esc(stamp(h.scanned_at) + ", grade " + h.grade) + '"><i></i></button>';
      }).join("");
      var first = history_[0], n = history_.length;
      var changes = history_.filter(function (h, i) { return i > 0 && history_[i - 1].grade !== h.grade; }).length;
      $("#d-scrub-n").textContent = n === 1 ? "One check stored so far. Each re-check adds a step here." :
        n + " checks since " + day(first.scanned_at) + ", " + changes + " grade change" + (changes === 1 ? "" : "s") + ". Scroll over the bars or use the arrow keys to move through time.";
      var sel = box.querySelector('[aria-current="true"]'); if (sel) sel.scrollIntoView({ block: "nearest", inline: "nearest" });
      box.onclick = function (e) { var b = e.target.closest("button[data-i]"); if (b) pick(+b.getAttribute("data-i")); };
      box.onwheel = function (e) { if (n < 2) return; e.preventDefault(); step(e.deltaY > 0 || e.deltaX > 0 ? 1 : -1); };
      box.onkeydown = function (e) { if (e.key === "ArrowRight") { e.preventDefault(); step(1); } else if (e.key === "ArrowLeft") { e.preventDefault(); step(-1); } };
    }
    function idx() { for (var i = 0; i < history_.length; i++) if (history_[i].scanned_at === current.scanned_at) return i; return history_.length - 1; }
    function step(dlt) { pick(Math.max(0, Math.min(history_.length - 1, idx() + dlt))); }
    function pick(i) {
      var h = history_[i]; if (!h || h.scanned_at === current.scanned_at) return;
      current = h.result;
      setParam("at", i === history_.length - 1 ? null : h.scanned_at);
      render();
      var box = $("#d-scrub"); if (box) box.focus({ preventScroll: true });
    }
    load(false);
  }

  /* The league: named organisations by sector, graded weekly by this server. */
  function viewLeague() {
    setView("league", "League");
    var sector = param("sector") || "", q = param("q") || "", sort = param("sort") || "grade", dir = param("dir") || "asc";
    say("Reading the league…");
    main.innerHTML = '<p class="i-eyebrow">League</p><h1 class="i-h1">Top sites by sector</h1><div id="lg-tabs" class="i-row"></div>' +
      '<div class="i-row"><label class="sr-only" for="lg-q">Filter by domain</label><div class="i-field"><span class="p">/</span><input id="lg-q" type="search" placeholder="filter domains" value="' + esc(q) + '"></div></div>' +
      '<div id="lg-body"></div>';
    var input = $("#lg-q"), t = null;
    input.addEventListener("input", function () { clearTimeout(t); t = setTimeout(function () { q = input.value.trim(); setParam("q", q); load(); }, 250); });
    function load() {
      var qs = "?limit=200&sort=" + enc(sort) + "&dir=" + enc(dir) + (sector ? "&sector=" + enc(sector) : "") + (q ? "&q=" + enc(q) : "");
      getJSON("/api/public/league" + qs, { cache: "no-store" }).then(paint).catch(function (e) { say("The league is not available right now."); $("#lg-body").innerHTML = '<div class="i-empty">' + esc(e.message) + "</div>"; });
    }
    function paint(L) {
      SECTORS = L.sectors || [];
      var cur = SECTORS.filter(function (s) { return s.id === sector; })[0];
      $("#lg-tabs").innerHTML = '<nav class="i-channels" aria-label="Sectors"><a href="/league' + (q ? "?q=" + enc(q) : "") + '"' + (!sector ? ' aria-current="page"' : "") + ">All</a>" +
        SECTORS.map(function (s) { return '<a href="/league?sector=' + enc(s.id) + (q ? "&q=" + enc(q) : "") + '"' + (s.id === sector ? ' aria-current="page"' : "") + ">" + esc(s.name) + " <small>" + num(s.graded) + "</small></a>"; }).join("") + "</nav>";
      var graded = cur ? cur.graded : L.graded, size = cur ? cur.count : L.list_size, share = cur ? cur.pq_share : null;
      if (!cur) { var pq = 0, g = 0; SECTORS.forEach(function (s) { if (s.pq_share != null) { pq += s.pq_share * s.graded; g += s.graded; } }); share = g ? pq / g : null; }
      say(!graded ? "No site in this list has been graded on this server yet." : byDepth({
        plain: "Of " + num(size) + " well-known " + (cur ? cur.name.toLowerCase() + " " : "") + "sites, " + num(graded) + " have been checked; " + pct(share) + " of those already protect their traffic against future quantum computers.",
        standard: num(graded) + " of " + num(size) + " named " + (cur ? cur.name : "") + " sites graded; " + pct(share) + " negotiate a post-quantum key exchange.",
        expert: num(graded) + "/" + num(size) + " graded under rubric " + L.rubric_version + "; post-quantum share " + pct(share) + "." }));
      var lr = L.last_run;
      var rows = L.rows || [];
      var head = function (k, label) { var on = sort === k; return '<th scope="col" aria-sort="' + (on ? (dir === "asc" ? "ascending" : "descending") : "none") + '"><a href="?' + new URLSearchParams(Object.assign({}, sector ? { sector: sector } : {}, q ? { q: q } : {}, { sort: k, dir: on && dir === "asc" ? "desc" : "asc" })).toString() + '">' + label + (on ? (dir === "asc" ? " ↑" : " ↓") : "") + "</a></th>"; };
      $("#lg-body").innerHTML = panel("CH1", cur ? cur.name : "All sectors",
        (cur && depth !== "plain" ? '<p class="i-fine">How sites get this label: ' + esc(cur.method) + "</p>" : "") +
        (rows.length ? '<div class="i-table-wrap"><table class="i-table"><thead><tr>' + head("domain", "Domain") + head("grade", "Grade") + '<th scope="col">Change</th><th scope="col">Key exchange</th>' + (sector ? "" : '<th scope="col">Sector</th>') + head("scanned", "Checked") + "</tr></thead><tbody>" +
          rows.map(function (r) {
            var ch = r.previous_grade && r.grade ? (r.previous_grade > r.grade ? '<span class="v-ok">up from ' + esc(r.previous_grade) + "</span>" : '<span class="v-bad">down from ' + esc(r.previous_grade) + "</span>") : "";
            return '<tr><td><a href="/' + esc(r.domain) + '">' + esc(r.domain) + "</a></td><td>" + (r.grade ? '<span class="g-chip" data-g="' + esc(r.grade) + '">' + esc(r.grade) + "</span>" : '<span class="i-dim">' + esc(r.miss ? "not reachable" : "not yet") + "</span>") + "</td><td>" + ch + '</td><td class="mono">' + esc(r.group || "") + "</td>" +
              (sector ? "" : "<td>" + esc((SECTORS.filter(function (s) { return s.id === r.sector; })[0] || {}).name || r.sector) + "</td>") + '<td class="mono">' + esc(r.scanned_at ? day(r.scanned_at) : "") + "</td></tr>";
          }).join("") + "</tbody></table></div>" + (L.total > rows.length ? '<p class="i-fine">Showing ' + num(rows.length) + " of " + num(L.total) + ". Narrow it with the filter.</p>" : "")
          : '<div class="i-empty">Nothing matches.</div>'),
        { right: lr ? "last batch " + esc(ago(lr.finished_at || lr.started_at)) + ": " + num(lr.graded) + " graded, " + num(lr.failed) + " unreachable" : "no batch has run yet" }) +
        '<p class="i-fine">This server re-grades every site in the list once a week, a few at a time, with the same check as the domain page: one set of TLS handshakes to port 443, nothing else. A site that asked not to be checked is left out. ' +
        'Labels come from <code>backend/league/sectors.json</code>: a name is listed only when its organisation and sector are public; nothing is guessed from the domain name.</p>';
    }
    load();
  }

  /* The atlas: every graded site as a cell, grouped by sector, zoomable; your estate if signed in. */
  function viewAtlas() {
    setView("atlas", "Atlas");
    say("Loading the atlas…");
    main.innerHTML = '<p class="i-eyebrow">Atlas</p><div class="i-row"><h1 class="i-h1">Every graded site, zoomable</h1></div>' +
      '<p class="i-fine">Scroll or pinch to zoom, drag to move, click a region to zoom into it, click a site when its name shows to open it. Keys: <kbd>+</kbd> <kbd>-</kbd> <kbd>0</kbd> and the arrows.</p>' +
      '<div class="ch" data-ch="atlas"><div class="ch-head"><span class="ch-n">MAP</span><span id="at-scope">all sectors</span><span class="ch-r" id="at-legend"></span></div><div class="atlas-wrap" id="at-wrap"></div></div><p class="i-fine" id="at-note"></p>';
    var estateP = token ? getJSON("/assets?limit=500", { auth: token, cache: "no-store" }).then(function (r) { return (r && (r.items || r)) || []; }).catch(function () { return null; }) : Promise.resolve(null);
    Promise.all([getJSON("/api/public/league?limit=500&sort=domain", { cache: "no-store" }), estateP]).then(function (res) {
      var L = res[0], estate = res[1];
      SECTORS = L.sectors || [];
      var groups = SECTORS.map(function (s) { return { id: s.id, name: s.name, cells: L.rows.filter(function (r) { return r.sector === s.id; }).map(function (r) { return { id: r.domain, label: r.domain, g: r.grade, href: "/" + r.domain }; }) }; })
        .filter(function (g) { return g.cells.length; });
      var nowY = new Date().getUTCFullYear();
      if (estate && estate.length) {
        var LIFE = { "1y": 1, "3y": 3, "5y": 5, "7y": 7, "10y": 10, "15y": 15, "20y": 20, "25y": 25, "30y": 30 };
        groups.unshift({ id: "estate", name: "Your estate", estate: true, cells: estate.map(function (a) {
          var life = parseInt(String(a.confidentiality_lifetime || "").replace(/[^0-9]/g, ""), 10);
          if (isNaN(life)) life = LIFE[a.confidentiality_lifetime];
          var until = isNaN(life) || life == null ? null : nowY + life;
          return { id: a.asset_key, label: a.asset_key + (until ? " · secret until " + until : ""), g: until == null ? null : until >= 2035 ? "E" : "B", href: "/ui/#assets" };
        }) });
      }
      var graded = L.rows.filter(function (r) { return r.grade; }).length;
      say(!graded && !(estate && estate.length) ? "Nothing has been graded on this server yet, so the atlas is empty." :
        byDepth({ plain: "Each square is a website; greener means better protected against future quantum computers.", standard: num(graded) + " graded sites in " + groups.length + " regions" + (estate && estate.length ? ", with your estate first" : "") + ". Colour is the grade.", expert: "Cells: league rows (rubric " + L.rubric_version + "); colour = grade; grey = not graded or unreachable." + (estate && estate.length ? " Estate cells: colour from confidentiality lifetime vs the 2035 earliest decrypt year." : "") }));
      $("#at-legend").innerHTML = ["A", "B", "C", "D", "E", "F"].map(function (g) { return '<span class="g-chip" data-g="' + g + '">' + g + "</span>"; }).join(" ");
      $("#at-note").textContent = estate && estate.length ? "Your estate region colours each asset by how long its data must stay secret (set in the console): amber when that runs past 2035, the earliest year recorded traffic could be read." : (token ? "Signed in, but no assets were readable for this account." : "");
      drawAtlas($("#at-wrap"), groups);
    }).catch(function (e) { say("The atlas could not load."); $("#at-wrap").innerHTML = '<div class="i-empty">' + esc(e.message) + "</div>"; });
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
          '<text class="atlas-cell-label" x="' + (cx + 1.2) + '" y="' + (cy + CELL / 2 + .9) + '">' + esc(c.id) + "</text></a>";
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
      svg.setAttribute("data-zoom", k > 7 ? "near" : k > 2.5 ? "mid" : "far");
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
      if (a && k > 7) return; // close enough to read names: follow the link
      e.preventDefault();
      var reg = e.target.closest(".atlas-region"); if (!reg) return;
      var fr = reg.querySelector(".atlas-frame"), bx = +fr.getAttribute("x"), by = +fr.getAttribute("y"), bw = +fr.getAttribute("width");
      if (a && k > 2.5) { var r2 = a.querySelector("rect"); var cx = +r2.getAttribute("x"), cy = +r2.getAttribute("y"); v = { x: cx - 40, y: cy - 40 * full.h / full.w, w: 80, h: 80 * full.h / full.w }; }
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
    main.innerHTML = '<p class="i-eyebrow">Reference</p><h1 class="i-h1">Algorithms</h1>' +
      '<nav class="i-channels" aria-label="Family"><a href="/algorithms"' + (!fam ? ' aria-current="page"' : "") + ">All</a>" + fams.map(function (f) { return '<a href="/algorithms?family=' + enc(f) + '"' + (fam === f ? ' aria-current="page"' : "") + ">" + f + "</a>"; }).join("") + "</nav>" +
      '<div class="ch-grid"><div class="span-7">' + panel("CH1", "The algorithms", '<div class="i-table-wrap"><table class="i-table"><thead><tr><th>Name</th><th>What it does</th><th>Against a quantum computer</th></tr></thead><tbody>' +
        list.map(function (a) { return '<tr><td><a href="/algorithms/' + a.id + '">' + esc(a.name) + "</a></td><td>" + esc(a.kind) + '</td><td class="' + riskTone(a.risk) + '">' + esc(ref.riskLabel[a.risk]) + "</td></tr>"; }).join("") + "</tbody></table></div>", { ch: "ref" }) + "</div>" +
      '<div class="span-5">' + panel("CH2", "The internet's cryptography, dated", timeline(ref.history.filter(function (h) { return !fam || h.a.some(function (id) { var x = ref.get(id); return x && x.family === fam; }) || !h.a.length; })), { ch: "ref" }) + "</div></div>";
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
      panel("CH1", "Against a quantum computer", '<p class="' + riskTone(a.risk) + '"><b>' + esc(ref.riskLabel[a.risk]) + "</b></p><p>" + esc(depth === "plain" ? a.summary : a.riskText) + "</p><p class=\"i-fine\">Status: " + esc(a.status) + "</p>", { ch: "ref" }) +
      (a.params && depth !== "plain" ? panel("CH2", "Sizes (bytes unless stated)", '<div class="i-table-wrap"><table class="i-table"><thead><tr>' + a.params.cols.map(function (c) { return "<th>" + esc(c) + "</th>"; }).join("") + "</tr></thead><tbody>" + a.params.rows.map(function (r) { return "<tr>" + r.map(function (c) { return "<td>" + esc(c) + "</td>"; }).join("") + "</tr>"; }).join("") + "</tbody></table></div>", { ch: "ref" }) : "") +
      (a.seenIn ? panel("CH3", "Where you meet it", "<p>" + esc(a.seenIn) + "</p>", { ch: "ref" }) : "") +
      "</div><div class=\"span-4\">" +
      (events.length ? panel("CH4", "Its history", timeline(events), { ch: "ref" }) : "") +
      panel("CH5", "Related", "<ul>" + a.related.map(function (r) { var x = ref.get(r); return x ? '<li><a href="/algorithms/' + r + '">' + esc(x.name) + "</a></li>" : ""; }).join("") + "</ul>", { ch: "ref" }) +
      panel("CH6", "Sources", "<ul>" + a.sources.map(function (s) { return '<li><a href="' + esc(s.href) + '" rel="noopener">' + esc(s.label) + "</a></li>"; }).join("") + "</ul>", { ch: "ref" }) +
      "</div></div>";
  }

  /* Trust: what this server runs, checked in this browser where a browser can check it. */
  function viewTrust() {
    setView("trust", "Trust");
    say("Checking what this server runs…");
    var asked = (param("commit") || "").toLowerCase();
    main.innerHTML = '<p class="i-eyebrow">Trust</p><h1 class="i-h1">What this server runs, and how to check it</h1>' +
      '<div class="ch-grid"><div class="span-6">' + panel("CH1", "Running commit", '<div id="tr-build" class="i-muted">Reading&hellip;</div>', { ch: "trust" }) + "</div>" +
      '<div class="span-6">' + panel("CH2", "This page's files against the signed manifest", '<div id="tr-man" class="i-muted">Reading&hellip;</div>', { ch: "trust" }) + "</div>" +
      '<div class="span-12">' + panel("CH3", "Deploy log", '<div id="tr-log" class="i-muted">Reading&hellip;</div>', { ch: "trust" }) + "</div>" +
      '<div class="span-6">' + panel("CH4", "No tracking: what this page contacted", '<div id="tr-req" class="i-muted">Reading&hellip;</div>', { ch: "trust" }) + "</div>" +
      '<div class="span-6">' + panel("CH5", "Rebuild it yourself", '<p>Release images are built reproducibly: two builds of the same commit give the same image digest, and each release image carries a keyless cosign signature and build attestations. The steps are in <a href="https://github.com/soqlab/Morrow/blob/main/docs/REPRODUCIBLE_BUILDS.md" rel="noopener">docs/REPRODUCIBLE_BUILDS.md</a>.</p>' +
        '<p>To check this server from a terminal, with a clone of the repository:</p><pre id="tr-cmd">python scripts/verify-deploy.py --url ' + esc(location.origin) + ' --repo .</pre><button type="button" class="i-btn" id="tr-copy">Copy</button>' +
        '<p class="i-fine">It compares every served file with the commit\'s source, checks the manifest\'s Ed25519 and ML-DSA-65 signatures, and recomputes the deploy log\'s hash chain.</p>', { ch: "tools" }) + "</div></div>";
    $("#tr-copy").addEventListener("click", function (e) { copy($("#tr-cmd").textContent, e.target); });
    var results = { build: null, files: null, sig: null, chain: null };
    function summary() {
      var b = results.build;
      if (!b) return;
      var parts = [];
      parts.push(b.commit ? "This server says it runs commit " + b.commit.slice(0, 12) + "." : "This server does not report its commit.");
      if (results.files != null) parts.push(results.files ? "The files this page loaded match its manifest." : "A file this page loaded does not match the manifest.");
      if (results.sig != null) parts.push(results.sig === true ? "The manifest's signature checks out in your browser." : results.sig === false ? "The manifest's signature does not verify." : "");
      if (results.chain != null) parts.push(results.chain ? "The deploy log's hash chain recomputes in your browser." : "The deploy log's hash chain does not recompute.");
      say(parts.filter(Boolean).join(" "));
    }
    getJSON("/api/public/build", { cache: "no-store" }).then(function (b) {
      results.build = b;
      var match = asked ? (b.commit && b.commit.indexOf(asked) === 0 ? '<p class="v-ok">Yes: commit ' + esc(asked) + " is the one this server reports.</p>" : '<p class="v-warn">No: this server reports ' + esc(b.commit || "no commit") + ", not " + esc(asked) + ".</p>") : "";
      $("#tr-build").innerHTML = match + (b.commit
        ? '<dl class="readouts">' + reading("Commit", '<a href="' + esc(b.commit_url) + '" rel="noopener">' + esc(b.commit) + "</a>") + reading("Reported by", esc(b.source || "-")) + reading("Process started", esc(stamp(b.started_at))) + reading("Python", esc(b.python || "-")) + "</dl>" +
          '<p class="i-fine">The commit comes from the hosting platform\'s build environment (' + esc(b.source) + '), not from the code itself, so the link above shows exactly the source that was deployed. The manifest on the right is how you check that claim.</p>'
        : "<p>The server was started without a commit in its environment, so it cannot say which source it runs. Self-hosters: set <code>MORROW_GIT_COMMIT</code>.</p>");
      summary();
    }).catch(function (e) { $("#tr-build").textContent = e.message; });

    Promise.all([getJSON("/api/public/manifest", { cache: "no-store" }), getJSON("/.well-known/morrow-proof-keys.json", { cache: "no-store" }).catch(function () { return null; })]).then(function (r) {
      var m = r[0], keys = r[1];
      var byPath = {}; (m.files || []).forEach(function (f) { byPath[f.path] = f; });
      var mine = ["/ui/instrument.html", "/ui/instrument.js", "/ui/instrument-data.js", "/ui/instrument.css"];
      return Promise.all(mine.map(function (p) {
        return fetch(p, { cache: "no-store" }).then(function (res) { return res.arrayBuffer(); }).then(sha256Hex).then(function (h) { return { path: p, mine: h, listed: byPath[p] ? byPath[p].sha256 : null }; });
      })).then(function (rows) {
        results.files = rows.every(function (x) { return x.listed && x.listed === x.mine; });
        var html = '<table class="i-table"><thead><tr><th>File</th><th>SHA-256 in your browser</th><th>Matches</th></tr></thead><tbody>' + rows.map(function (x) {
          return '<tr><td class="mono">' + esc(x.path) + '</td><td class="mono"><small>' + esc(x.mine.slice(0, 16)) + "&hellip;</small></td><td class=\"" + (x.listed === x.mine ? "v-ok\">yes" : "v-bad\">no") + "</td></tr>";
        }).join("") + "</tbody></table><p class=\"i-fine\">" + num((m.files || []).length) + " files listed for commit " + esc((m.commit || "unknown").slice(0, 12)) + ", generated " + esc(stamp(m.generated_at)) + ".</p>";
        var ed = (m.signatures || []).filter(function (s) { return s.alg === "Ed25519"; })[0];
        var ml = (m.signatures || []).filter(function (s) { return s.alg === "ML-DSA-65"; })[0];
        var key = ed && keys && (keys.keys || []).filter(function (k) { return k.kid === ed.kid; })[0];
        $("#tr-man").innerHTML = html + '<p id="tr-sig">' + (m.signatures && m.signatures.length ? "Checking the signature&hellip;" : "The manifest is not signed on this server: " + esc(m.unsigned_reason || "no reason given")) + "</p>";
        summary();
        if (!ed || !key) { if (m.signatures && m.signatures.length) $("#tr-sig").textContent = "No Ed25519 key published for this signature."; return; }
        var body = {}; Object.keys(m).forEach(function (k) { if (k !== "signatures" && k !== "unsigned_reason") body[k] = m[k]; });
        var bytes = new TextEncoder().encode(m.signing_context + canonical(body));
        return crypto.subtle.importKey("raw", b64bytes(key.public_key), { name: "Ed25519" }, false, ["verify"])
          .then(function (k) { return crypto.subtle.verify({ name: "Ed25519" }, k, b64bytes(ed.sig_b64), bytes); })
          .then(function (ok) {
            results.sig = ok;
            $("#tr-sig").innerHTML = (ok ? '<span class="v-ok">Ed25519 signature verified in your browser</span>' : '<span class="v-bad">Ed25519 signature did not verify</span>') + " with key <code>" + esc(key.kid) + "</code>." +
              (ml ? ' The manifest also carries an ML-DSA-65 signature (<code>' + esc(ml.kid) + '</code>). Browsers cannot check ML-DSA yet, so this page does not; <code>verify-deploy.py</code> does.' : "");
            summary();
          }, function () { $("#tr-sig").textContent = "This browser cannot check Ed25519 signatures, so the signature was not checked here. verify-deploy.py checks it."; });
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

  /* ── start ─────────────────────────────────────────────────────────────── */
  dial();
  paintConnStrip();
  footer();
  var cb = $("#i-cmd-btn"); if (cb) cb.addEventListener("click", openPalette);
  route();
})();
