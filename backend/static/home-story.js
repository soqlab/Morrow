/*
 * The front page's story (instrument.js calls MorrowHome.mount() for "/"). The first screen, the
 * question and the domain box, is already in the HTML (services/home_page.py); this script makes it
 * answer in place and draws the rest of the story under it, from public data only:
 *
 *   /api/public/stats                          "N sites checked this week" and the share ready,
 *                                              read again every 25 s while the tab is visible
 *   /api/public/checked-safe?order=popular     the row of well-known sites that are ready
 *   /api/public/not-ready?order=popular        the row of well-known sites that are not yet
 *                                              (both with hide_infra=1: CDN, API, ad and tracking
 *                                              hosts are left out of the rows, services/infra_hosts.py)
 *   /api/public/league                         sector bars, and the headline written from its spread
 *   /api/public/grade/<domain>                 the check, under that route's limits and opt-out
 *   /api/public/make-safe/<domain>             whether Done (one click) applies to the answer
 *
 * Rules it keeps: a number on screen came from one of those answers in this page load; names are
 * dated measurements, best-known first (the Tranco order), never ranked by grade; the reply,
 * correction and opt-out links sit next to the names. Same origin only, nothing inline (styles are
 * set through the CSSOM). Motion: see home-story.css. Everything here also works with
 * prefers-reduced-motion, where every value is simply there.
 */
(function () {
  "use strict";
  var POLL_MS = 25000;
  var ROW = 24;
  var REDUCED = !!(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches);
  var MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

  function I() { return window.MorrowIns; }
  function $(s, r) { return (r || document).querySelector(s); }
  function esc(v) { return I().esc(v); }
  function enc(v) { return encodeURIComponent(v); }
  function num(n) { return n == null || isNaN(n) ? "-" : Math.round(Number(n)).toLocaleString("en-GB"); }
  function when(iso) {
    var d = new Date(iso); if (!iso || isNaN(d)) return "an unknown date";
    return d.getUTCDate() + " " + MONTHS[d.getUTCMonth()] + " " + d.getUTCFullYear();
  }
  function later(fn, ms) { return setTimeout(fn, REDUCED ? 0 : ms); }

  /* A number counting up once, eased (straight to the value under reduced motion). */
  function countUp(el, to, ms, fmt) {
    fmt = fmt || num;
    if (!el) return;
    if (REDUCED || !window.requestAnimationFrame) { el.textContent = fmt(to); return; }
    var t0 = null;
    (function step(t) {
      if (t0 == null) t0 = t;
      var k = Math.min(1, (t - t0) / ms), e = 1 - Math.pow(1 - k, 4);
      el.textContent = fmt(to * e);
      if (k < 1) requestAnimationFrame(step);
    })(performance.now());
  }
  /* A number that rose: the digits that changed roll in (instrument-board.css .fb-roll). */
  function roll(el, text) {
    var old = el.textContent;
    if (REDUCED || old === text) { el.textContent = text; return; }
    var off = old.length - text.length, out = "", n = 0;
    for (var i = text.length - 1; i >= 0; i--) {
      var ch = text.charAt(i), was = old.charAt(i + off);
      out = (ch !== was && /\d/.test(ch) ? '<span class="fb-roll fb-roll-' + Math.min(5, n++) + '">' + esc(ch) + "</span>" : esc(ch)) + out;
    }
    el.innerHTML = out;
  }

  /* ── live counts: one reading every 25 s while the tab is visible, shared with the board ── */
  var S = { stats: null, subs: [], poll: 0, counted: false, safe: null, not: null, demoNames: [] };
  function sites(s) {
    // Distinct sites by their newest check this week; an older server only reports checks.
    if (s && s.sites_checked_7d != null) return { n: s.sites_checked_7d, ready: s.sites_ready_7d || 0, share: s.sites_ready_share_7d || 0, unit: "sites" };
    var n = (s && s.public_checks_7d) || 0, sh = (s && s.pq_share_7d) || 0;
    return { n: n, ready: Math.round(n * sh), share: sh, unit: "checks" };
  }
  function ping() {
    var d = $("#hs-dot"); if (!d) return;
    d.setAttribute("data-live", "on");
    if (REDUCED) return;
    d.classList.remove("hs-ping"); void d.offsetWidth; d.classList.add("hs-ping");
  }
  function paintLive(s, first) {
    var v = sites(s), el = $("#hs-sites"), t = $("#hs-sites-t");
    if (!el) return;
    if (t) t.textContent = v.unit === "sites" ? (v.n === 1 ? "site checked this week" : "sites checked this week") : (v.n === 1 ? "check this week" : "checks this week");
    if (first) countUp(el, v.n, 1600); else roll(el, num(v.n));
    ping();
  }
  function read() {
    if (document.hidden) return;
    I().getJSON("/api/public/stats", { cache: "no-store", timeout: 15000 }).then(function (s) {
      var was = S.stats; S.stats = s;
      paintLive(s, !was);
      if (was) paintNow(s);
      S.subs.forEach(function (fn) { try { fn(s); } catch (e) { /* a subscriber's own problem */ } });
    }).catch(function () { var d = $("#hs-dot"); if (d) d.setAttribute("data-live", "off"); });
  }
  function onStats(fn) { S.subs.push(fn); }

  /* ── the check, answered in place ── */
  var DISC = '<div class="hs-disc" data-state="wait" aria-hidden="true"><span class="hs-d-wait">?</span><span class="hs-d-warn"></span><span class="hs-d-safe"></span></div>';
  var seq = 0;
  function card(state, body) { return '<div class="hs-card" data-state="' + state + '">' + DISC + '<div class="hs-ans-body">' + body + "</div></div>"; }
  function busy(d) {
    var box = $("#hs-answer");
    box.innerHTML = card("busy", '<p class="hs-ans-dom">' + esc(d) + '</p><p class="hs-busy-t" role="status">Checking <b>' + esc(d) + "</b>&hellip; Morrow opens a few TLS connections to its port 443. A first check can take up to half a minute.</p>" +
      '<span class="hs-prog" aria-hidden="true"><i></i></span>');
    var p = $(".hs-prog", box);
    if (p && !REDUCED) requestAnimationFrame(function () { requestAnimationFrame(function () { p.classList.add("hs-go"); }); });
    reveal(box);
  }
  function reveal(box) {
    var c = box.firstElementChild; if (!c || !c.getBoundingClientRect) return;
    var r = c.getBoundingClientRect();
    if (r.bottom > window.innerHeight || r.top < 0) c.scrollIntoView({ block: "nearest", behavior: REDUCED ? "auto" : "smooth" });
  }
  function notChecked(d, e) {
    var msg = (e && e.message) || "The check did not finish.";
    if (e && e.retryAfter) msg += " Try again in " + e.retryAfter + " s.";
    $("#hs-answer").innerHTML = card("error", '<p class="hs-ans-dom">' + esc(d) + '</p><p class="hs-verdict" data-tone="warn">Not checked</p><p class="hs-err">' + esc(msg) + "</p>" +
      '<p class="hs-more"><a href="/' + enc(d) + '">Open its page</a><a href="/plain/' + enc(d) + '">Plain version</a></p>');
  }
  function answer(d, r, plan) {
    var g = String(r.grade || "?"), safe = g === "A" || g === "B";
    var kx = (r.key_exchange || {}).group || "";
    var risk = (r.risk && r.risk.sentence) || r.summary || "";
    var oneClick = !safe && plan && plan.one_click;
    var act = safe ? '<a class="hs-btn" href="/r/' + enc(d) + '">See the full record</a>'
      : oneClick ? "" : '<a class="hs-btn" href="/r/' + enc(d) + '">See how to fix it</a>';
    var more = (safe ? "" : '<a href="/r/' + enc(d) + '">See the full record &rarr;</a>') +
      "<span>Measured " + esc(when(r.scanned_at)) + (kx ? ", key exchange " + esc(kx) : "") + "</span>";
    var box = $("#hs-answer");
    box.innerHTML = card(safe ? "safe" : "warn",
      '<p class="hs-ans-dom">' + esc(d) + "</p>" +
      '<p class="hs-verdict" data-tone="' + (safe ? "safe" : "warn") + '"><span class="sr-only">' + esc(d) + ": grade " + esc(g) + ". </span>" + (safe ? "Quantum-safe." : "Not quantum-safe yet") + "</p>" +
      (risk ? '<p class="hs-risk">' + esc(risk) + "</p>" : "") +
      '<div class="hs-act" id="home-make-safe">' + act + "</div>" +
      '<p class="hs-more">' + more + "</p>");
    var disc = $(".hs-disc", box);
    $(".hs-d-warn", disc).textContent = g;
    $(".hs-d-safe", disc).textContent = g;
    // The same motion as the Done card: the answer lands, and a safe one turns green and glows.
    later(function () { disc.setAttribute("data-state", safe ? "safe" : "warn"); }, 260);
    // Done (make-safe-done.js) offers itself right under the action when one click applies.
    I().makeSafeRendered($("#home-make-safe"), { source: "home", domain: d, plan: oneClick ? plan : null });
    reveal(box);
  }
  function check(d) {
    var mine = ++seq, go = $("#hs-go");
    if (go) go.setAttribute("aria-busy", "true");
    busy(d);
    I().getJSON("/api/public/grade/" + enc(d), { timeout: 60000 }).then(function (r) {
      var safe = r && (r.grade === "A" || r.grade === "B");
      var plan = safe ? Promise.resolve(null) : I().getJSON("/api/public/make-safe/" + enc(d), { timeout: 20000 }).catch(function () { return null; });
      return plan.then(function (p) { if (mine === seq) answer(d, r, p); });
    }).catch(function (e) { if (mine === seq) notChecked(d, e); })
      .then(function () { if (go && mine === seq) go.removeAttribute("aria-busy"); });
  }

  function bindHero() {
    var form = $("#home-form"), input = $("#home-q"), hint = $("#home-hint");
    var paste = window.MorrowPaste, guided = window.MorrowGuided;
    var HINT = hint.textContent;
    var quiet = $("#hs-quiet");
    quiet.innerHTML = '<span>Or paste or drop a certificate, a server config, a CBOM or a .pcap.</span>' +
      '<button type="button" class="pa-pick" id="home-pick">Choose a file</button>' +
      '<input type="file" id="home-file" class="sr-only" tabindex="-1" aria-hidden="true">' +
      '<button type="button" class="hs-cmd" id="hs-cmd"><kbd>Ctrl K</kbd> for anything else</button>' +
      (guided ? guided.switchHtml(false) : "");
    if (guided) guided.bindSwitch(form);
    $("#hs-cmd").addEventListener("click", function () { var b = $("#i-cmd-btn"); if (b) b.click(); });
    input.setAttribute("aria-describedby", "home-hint hs-quiet");
    if (paste) paste.attach({ form: form, input: input, hint: hint, out: $("#paste-out") });
    else input.addEventListener("keydown", function (e) { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); form.requestSubmit ? form.requestSubmit() : form.submit(); } });
    input.addEventListener("input", function () {
      var d = I().asDomain(input.value);
      if (d && !(paste && paste.wants(input.value))) { hint.setAttribute("data-tone", "ok"); hint.textContent = "Press Enter to check " + d + "."; }
      else { hint.removeAttribute("data-tone"); hint.textContent = HINT; }
    });
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      if (paste && paste.wants(input.value)) { paste.read(input.value); return; }
      var d = I().asDomain(input.value);
      if (!d) {
        hint.setAttribute("data-tone", "no");
        hint.textContent = input.value.trim() ? "That isn't a domain, a certificate or a config file Morrow knows. Type a domain like example.com, or paste the whole file." : "Type your domain first, like example.com.";
        input.focus();
        return;
      }
      hint.removeAttribute("data-tone"); hint.textContent = HINT;
      I().remember("domain", d, d);
      check(d);
    });
  }

  /* Real names typing themselves into the box while it is empty, unfocused and on screen; a few
     names, then it rests on a plain example. */
  function typeDemo() {
    var input = $("#home-q"), hero = $("#hs-hero"), names = S.demoNames.slice(0, 8), i = 0;
    if (REDUCED || !names.length || !input) return;
    function idle() { return document.activeElement !== input && !input.value && !document.hidden && hero.classList.contains("hs-on"); }
    function next() {
      if (i >= names.length) { input.placeholder = "yourcompany.com"; return; }
      if (!idle()) { setTimeout(next, 1500); return; }
      var w = names[i++], k = 0;
      (function type() {
        if (!idle()) { input.placeholder = "yourcompany.com"; setTimeout(next, 1500); return; }
        input.placeholder = w.slice(0, ++k);
        if (k < w.length) { setTimeout(type, 70); return; }
        setTimeout(function erase() {
          if (!idle()) { input.placeholder = "yourcompany.com"; setTimeout(next, 1500); return; }
          input.placeholder = input.placeholder.slice(0, -1);
          if (input.placeholder) setTimeout(erase, 35); else setTimeout(next, 300);
        }, 1500);
      })();
    }
    next();
  }

  /* ── the story ── */
  function story() {
    return '<div class="hs-wrap" id="home-reading"></div>' +
      '<section class="hs-now hs-wrap" id="hs-now" aria-labelledby="hs-now-h">' +
        '<p class="hs-kicker hs-rv">Right now, on Morrow</p>' +
        '<div class="hs-rv" data-on="now"><p class="hs-big" aria-hidden="true"><span id="hs-pct">0</span><sup>%</sup></p></div>' +
        '<h2 class="hs-h2 hs-rv" id="hs-now-h"><span class="sr-only" id="hs-pct-sr"></span><span id="hs-now-say">of the sites checked this week are ready for quantum computers.</span> <span class="hs-mute" id="hs-now-rest">The rest aren&rsquo;t yet.</span></h2>' +
        '<div class="hs-rv" data-on="split"><div class="hs-split" id="hs-split-bar" role="img" aria-label="Share of sites ready"><i id="hs-split"></i></div>' +
          '<p class="hs-legend"><span><b id="hs-ready">0</b> ready</span><span class="hs-r"><b id="hs-notyet">0</b> not yet</span></p></div>' +
        '<p class="hs-fine hs-rv" id="hs-now-fine">Ready means the site agreed a post-quantum key exchange in its newest check this week (grade A or B). Each site is counted once. <a href="/report">How it is counted</a></p>' +
      "</section>" +
      '<section class="hs-names" id="hs-names" aria-labelledby="hs-names-h">' +
        '<div class="hs-wrap hs-rv"><p class="hs-kicker">Measured this week</p><h2 class="hs-h2" id="hs-names-h">Who&rsquo;s ready.<br><span class="hs-mute">Who isn&rsquo;t.</span></h2></div>' +
        '<div class="hs-row" data-dir="fwd" id="hs-row-ok" role="group" aria-label="Well-known sites whose newest check is quantum-safe"><p class="hs-row-empty">Reading the names&hellip;</p></div>' +
        '<div class="hs-row" data-dir="rev" id="hs-row-no" role="group" aria-label="Well-known sites that are not yet post-quantum"><p class="hs-row-empty">&nbsp;</p></div>' +
        '<p class="hs-fine hs-rv">Each name is one dated measurement of its public key exchange, made the same way for every site (<a href="/about-scanner">how Morrow checks</a>). ' +
          "Not a ranking: well-known sites from the Tranco list, best-known first. Hover or focus a name for its date and key exchange. " +
          'Owners can <a href="/league#nr-correct">reply or ask for a correction</a>, or <a href="/abuse">opt out</a>. <a class="hs-all" id="hs-all" href="/league">See all &rarr;</a></p>' +
      "</section>" +
      '<section class="hs-done hs-wrap" id="hs-done" aria-labelledby="hs-done-h">' +
        '<div class="hs-rv"><p class="hs-kicker">Then fix it</p><h2 class="hs-h2" id="hs-done-h">One click.<br><span class="hs-ok">Done.</span></h2>' +
          '<p class="hs-lede">Where your DNS is on Cloudflare, Morrow makes the change, checks it from the outside, and hands you a signed proof. Everywhere else, the exact change for your server.</p></div>' +
        '<div class="hs-rv" data-on="demo"><div class="hs-demo" id="hs-demo">' +
          '<p class="hs-demo-dom"><span>YOURCOMPANY.COM</span><span class="hs-demo-tag">Example</span></p>' +
          '<div class="hs-disc" data-state="warn" id="hs-demo-disc" aria-hidden="true"><span class="hs-d-wait">?</span><span class="hs-d-warn">C</span><span class="hs-d-safe">A</span></div>' +
          '<ol class="hs-steps" id="hs-steps"><li><span class="hs-tick" aria-hidden="true"></span><span class="hs-st">Changing the setting</span></li>' +
            '<li><span class="hs-tick" aria-hidden="true"></span><span class="hs-st">Checking from the outside</span></li>' +
            '<li><span class="hs-tick" aria-hidden="true"></span><span class="hs-st">Signing the proof</span></li></ol>' +
          '<p class="hs-verdict-demo" id="hs-demo-v">Quantum-safe.</p>' +
          '<button type="button" class="hs-replay" id="hs-replay"><span aria-hidden="true">&#8635;</span> Play again</button>' +
          '<p class="sr-only" id="hs-demo-sr" aria-live="polite"></p>' +
        "</div></div>" +
      "</section>" +
      '<section class="hs-sectors hs-wrap" id="hs-sectors" aria-labelledby="hs-sec-h">' +
        '<div class="hs-rv"><p class="hs-kicker">By sector</p><h2 class="hs-h2" id="hs-sec-h">Every sector, measured.</h2></div>' +
        '<ul class="hs-bars" id="hs-bars"></ul>' +
        '<p class="hs-fine hs-rv">The share of each sector&rsquo;s well-known sites whose newest check is A or B. Averages: no site is named. <a href="/report">Sector reports</a>, with their trend and method.</p>' +
      "</section>" +
      '<section class="hs-final" id="hs-final" aria-labelledby="hs-final-h">' +
        '<div class="hs-rv"><h2 class="hs-h2" id="hs-final-h">Your turn.</h2></div>' +
        '<form class="hs-check hs-rv" id="hs-form2" novalidate><label class="sr-only" for="hs-q2">Your website&rsquo;s address</label>' +
          '<div class="hs-box"><textarea id="hs-q2" rows="1" autocomplete="url" autocapitalize="none" spellcheck="false" inputmode="url" placeholder="yourcompany.com"></textarea>' +
          '<button type="submit" class="hs-btn">Check it</button></div></form>' +
      "</section>" +
      '<section class="hs-board hs-wrap" id="hs-board" aria-labelledby="hs-board-h">' +
        '<p class="hs-kicker">The full board</p><h2 class="hs-h2" id="hs-board-h">Every name,<br><span class="hs-mute">every sector.</span></h2>' +
        '<p class="hs-lede">Find a company, pick a sector, see what just changed. The same live data, all of it.</p>' +
        '<div id="home-board"></div>' +
      "</section>";
  }

  /* 2. The share ready, from the same reading as the hero's count: counted up when it scrolls into
     view, and after that a new reading simply moves it. */
  function setNow(v, pct) {
    $("#hs-pct").textContent = String(pct);
    roll($("#hs-ready"), num(v.ready)); roll($("#hs-notyet"), num(v.n - v.ready));
    $("#hs-split").style.transform = "scaleX(" + v.share + ")";
  }
  function paintNow(s) {
    var v = sites(s), pct = Math.round(v.share * 100);
    var say = $("#hs-now-say"), sr = $("#hs-pct-sr");
    if (!say) return;
    if (!v.n) {
      say.textContent = "No site has been checked on this server in the last 7 days yet.";
      $("#hs-now-rest").textContent = ""; $("#hs-pct").textContent = "-"; return;
    }
    say.textContent = v.unit === "sites" ? "of the sites checked this week are ready for quantum computers."
      : "of this week’s checks found a key exchange ready for quantum computers.";
    if (sr) sr.textContent = pct + "% ";
    $("#hs-split-bar").setAttribute("aria-label", num(v.ready) + " ready, " + num(v.n - v.ready) + " not yet, of " + num(v.n) + " " + v.unit + " this week");
    S.nowV = v;
    if (S.nowShown) setNow(v, pct); else if (S.nowWanted) playNow();
  }
  function playNow() {
    S.nowWanted = true;
    var v = S.nowV; if (!v || S.nowShown) return;
    S.nowShown = true;
    countUp($("#hs-pct"), Math.round(v.share * 100), 2000, function (x) { return String(Math.round(x)); });
    countUp($("#hs-ready"), v.ready, 2000); countUp($("#hs-notyet"), v.n - v.ready, 2000);
    $("#hs-split").style.transform = "scaleX(" + v.share + ")";
  }

  /* 3. Two rows of names. Each name opens its permanent record. */
  function pills(list, tone) {
    return list.map(function (e) {
      var kx = e.key_exchange || (tone === "ok" ? "post-quantum" : "not observed");
      var tip = e.domain + " · measured " + when(e.checked_at) + " · key exchange " + kx;
      return '<li><a class="hs-pill" data-tone="' + tone + '" href="/r/' + enc(e.domain) + '" title="' + esc(tip) + '">' +
        '<span class="hs-g" aria-hidden="true">' + esc(e.grade || "-") + "</span>" + esc(e.domain) +
        '<span class="sr-only">: grade ' + esc(e.grade || "unknown") + ", measured " + esc(when(e.checked_at)) + ", key exchange " + esc(kx) + "</span></a></li>";
    }).join("");
  }
  function paintRow(id, body, tone, empty) {
    var row = $("#" + id); if (!row) return;
    var list = (body && body.entries) || [];
    if (!list.length) { row.innerHTML = '<p class="hs-row-empty">' + esc(empty) + "</p>"; return; }
    var h = pills(list, tone);
    // The second copy only closes the loop of the moving row: hidden from assistive technology and
    // out of the tab order (inert), and not shown at all under reduced motion.
    row.innerHTML = '<ul class="hs-track">' + h + '</ul><ul class="hs-track" aria-hidden="true" inert>' + h + "</ul>";
    var track = row.firstElementChild;
    var px = track.scrollWidth || 2400;
    row.style.setProperty("--hs-dur", Math.max(30, Math.round(px / 45)) + "s");
  }
  function loadNames() {
    var safe = I().getJSON("/api/public/checked-safe?order=popular&days=8&limit=" + ROW + "&hide_infra=1", { timeout: 20000 })
      .then(function (Q) { S.safe = Q; paintRow("hs-row-ok", Q, "ok", "No well-known site was graded A or B in the last 8 days."); return Q; })
      .catch(function () { paintRow("hs-row-ok", null, "ok", "The quantum-safe names could not be read just now."); return null; });
    var not = I().getJSON("/api/public/not-ready?order=popular&limit=" + ROW + "&hide_infra=1", { timeout: 20000 })
      .then(function (N) {
        S.not = N; paintRow("hs-row-no", N, "warn", "No well-known site is below B on this server.");
        var all = $("#hs-all");
        if (all && N.count) all.innerHTML = "See all " + num(N.count) + '<span class="sr-only"> sites not yet post-quantum</span> &rarr;';
        return N;
      })
      .catch(function () { paintRow("hs-row-no", null, "warn", "The not-yet-post-quantum names could not be read just now."); return null; });
    Promise.all([safe, not]).then(function (r) {
      var a = ((r[0] || {}).entries || []).map(function (e) { return e.domain; }), b = ((r[1] || {}).entries || []).map(function (e) { return e.domain; });
      for (var i = 0; i < Math.max(a.length, b.length); i++) { if (a[i]) S.demoNames.push(a[i]); if (b[i]) S.demoNames.push(b[i]); }
      typeDemo();
    });
  }

  /* 4. The Done sequence, played once when it scrolls into view, and again on request. */
  var demoT = [];
  function playDemo() {
    demoT.forEach(clearTimeout); demoT = [];
    var disc = $("#hs-demo-disc"), steps = document.querySelectorAll("#hs-steps li"), v = $("#hs-demo-v"), sr = $("#hs-demo-sr");
    disc.setAttribute("data-state", "warn"); v.classList.remove("on");
    Array.prototype.forEach.call(steps, function (li) { li.classList.remove("on"); });
    [700, 1600, 2400].forEach(function (ms, i) { demoT.push(later(function () { steps[i].classList.add("on"); }, ms)); });
    demoT.push(later(function () { disc.setAttribute("data-state", "safe"); v.classList.add("on"); if (sr) sr.textContent = "Example: grade C to A, quantum-safe."; }, 3000));
  }

  /* 5. Sector bars, and the headline written from the league's spread. */
  function pct1(x) { return Math.round((x || 0) * 100); }
  function paintSectors(L) {
    var list = ((L && L.sectors) || []).filter(function (s) { return s.graded && s.pq_share != null; })
      .sort(function (a, b) { return b.pq_share - a.pq_share || String(a.name).localeCompare(String(b.name)); });
    var h = $("#hs-sec-h"), sp = L && L.spread;
    if (sp && sp.ahead && sp.behind) {
      h.innerHTML = esc(sp.ahead.name) + ", ahead.<br><span class=\"hs-mute\">" + esc(sp.behind.name) + ", behind.</span>" +
        '<span class="sr-only"> ' + pct1(sp.ahead.pq_share) + "% against " + pct1(sp.behind.pq_share) + "%.</span>";
    } else if (list.length === 1) {
      h.innerHTML = esc(list[0].name) + ": " + pct1(list[0].pq_share) + "% ready.";
    }
    var box = $("#hs-bars");
    if (!list.length) { box.innerHTML = '<li class="hs-fine">No sector has been graded on this server yet. The sector lists are re-checked weekly.</li>'; return; }
    box.innerHTML = list.map(function (s) {
      return '<li class="hs-bar hs-rv" data-on="bar"><a href="/report/' + enc(s.id) + '">' + esc(s.name) + '</a><span class="t" aria-hidden="true"><i class="f" data-share="' + s.pq_share + '"></i></span>' +
        '<span class="p" data-p="' + pct1(s.pq_share) + '">' + (REDUCED ? pct1(s.pq_share) : 0) + '%</span><span class="sr-only"> of ' + num(s.graded) + " graded sites ready</span></li>";
    }).join("");
    Array.prototype.forEach.call(box.children, function (li, i) { li.style.transitionDelay = (i % 9) * 70 + "ms"; watch(li); });
  }

  /* ── what is on screen: reveals once, and the two moving parts run only while visible ── */
  var reveals = null, ambient = null;
  function onReveal(el) {
    var what = el.getAttribute("data-on");
    if (what === "now" || what === "split") playNow();
    else if (what === "demo" && !S.demoPlayed) { S.demoPlayed = true; playDemo(); }
    else if (what === "bar") {
      var f = $(".f", el), p = $(".p", el);
      if (f) f.style.transform = "scaleX(" + Number(f.getAttribute("data-share")) + ")";
      if (p) countUp(p, Number(p.getAttribute("data-p")), 1600, function (x) { return Math.round(x) + "%"; });
    }
  }
  function watch(el) {
    if (reveals) reveals.observe(el);
    else { el.classList.add("hs-in"); onReveal(el); }
  }
  function observe(root) {
    if (window.IntersectionObserver && !REDUCED) {
      reveals = new IntersectionObserver(function (entries) {
        entries.forEach(function (en) {
          if (!en.isIntersecting) return;
          en.target.classList.add("hs-in"); reveals.unobserve(en.target); onReveal(en.target);
        });
      }, { threshold: 0.2 });
      ambient = new IntersectionObserver(function (entries) {
        entries.forEach(function (en) { en.target.classList.toggle("hs-on", en.isIntersecting); });
      }, { threshold: 0 });
      ambient.observe($("#hs-hero")); ambient.observe($("#hs-names"));
    } else {
      $("#hs-hero").classList.toggle("hs-on", !REDUCED);
    }
    Array.prototype.forEach.call(root.querySelectorAll(".hs-rv"), watch);
  }

  function nav() {
    var right = $(".i-top-right"); if (!right || $(".hs-nav")) return;
    var n = document.createElement("nav");
    n.className = "hs-nav"; n.setAttribute("aria-label", "On this page");
    n.innerHTML = '<a href="#hs-names">Who&rsquo;s ready</a><a href="#hs-done">How it works</a><a href="#hs-sectors">Sectors</a><a href="#hs-board">Every name</a>';
    right.parentNode.insertBefore(n, right);
    // The depth dial lives in the footer here; it is the same element, so it keeps working.
    var dial = $("#i-dial"), foot = $(".i-foot-in");
    if (dial && foot) foot.appendChild(dial);
    var cmd = $("#i-cmd-btn");
    if (cmd) {
      cmd.setAttribute("aria-label", "Search: a domain, an algorithm, a scan, a place (Ctrl K)");
      var ic = cmd.querySelector('span[aria-hidden="true"]');
      if (ic) ic.innerHTML = '<svg class="hs-search" viewBox="0 0 20 20" width="16" height="16" focusable="false"><circle cx="8.5" cy="8.5" r="5.5" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M13 13l4.5 4.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>';
    }
    var top = $(".i-top");
    var onScroll = function () { if (top) top.classList.toggle("hs-scrolled", window.scrollY > 20); };
    window.addEventListener("scroll", onScroll, { passive: true }); onScroll();
  }

  function mount() {
    var hero = $("#hs-hero"), slot = $("#hs-story");
    if (!hero || !slot || !window.MorrowIns) return false;
    nav();
    bindHero();
    slot.innerHTML = story();
    observe(slot);
    $("#hs-replay").addEventListener("click", playDemo);
    $("#hs-form2").addEventListener("submit", function (e) {
      e.preventDefault();
      var q = $("#hs-q2"), top = $("#home-q");
      top.value = q.value; q.value = "";
      window.scrollTo({ top: 0, behavior: REDUCED ? "auto" : "smooth" });
      var f = $("#home-form"); if (f.requestSubmit) f.requestSubmit(); else f.dispatchEvent(new Event("submit", { cancelable: true }));
    });
    $("#hs-q2").addEventListener("keydown", function (e) { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); $("#hs-form2").requestSubmit(); } });
    I().getJSON("/api/public/stats", { cache: "no-store", timeout: 15000 }).then(function (s) {
      S.stats = s; paintLive(s, true); paintNow(s);
      if (REDUCED || !window.IntersectionObserver) playNow();
      S.subs.forEach(function (fn) { try { fn(s); } catch (e) { /* ignore */ } });
      S.poll = setInterval(read, POLL_MS);
      document.addEventListener("visibilitychange", function () {
        if (document.hidden) { var d = $("#hs-dot"); if (d) d.setAttribute("data-live", "off"); } else read();
      });
    }).catch(function () {
      var t = $("#hs-sites-t"); if (t) t.textContent = "this week’s count could not be read just now";
      var say = $("#hs-now-say"); if (say) say.textContent = "This week’s share could not be read just now. The domain box above still works.";
    });
    loadNames();
    I().getJSON("/api/public/league", { timeout: 20000 }).then(paintSectors).catch(function () {
      $("#hs-bars").innerHTML = '<li class="hs-fine">The sector averages could not be read just now. <a href="/league">Open the league</a>.</li>';
    });
    I().connection().then(function (c) { var t = $("#home-conn"); if (t) t.textContent = I().connLine(c); });
    if (window.MorrowBoard) { window.MorrowBoard.mount($("#home-board")); window.MorrowBoard.welcomeBack($("#home-back")); }
    I().workspace().then(function (w) { if (w && I().homeSignedIn) I().homeSignedIn(); });
    if (!REDUCED) document.documentElement.classList.add("hs-smooth");
    return true;
  }

  window.MorrowHome = { mount: mount, onStats: onStats };
})();
