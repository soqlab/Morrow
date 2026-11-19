/*
 * The front page's live board: who is quantum-safe (instrument.js calls MorrowBoard.mount()).
 *
 * Under the domain box on "/". Everything on it is public and needs no account: it reads only
 * /api/public/stats, /league, /changes, /checked-safe, /pq-ready and /not-ready, after the page has
 * painted, in parallel, and keeps each answer for two minutes in this tab (sessionStorage). The
 * domain box works whether or not any of it arrives; each part says plainly what is missing.
 *
 * What it keeps from the league page (services/not_ready.py, services/changes.py, pq_ready.py):
 *   - Sites are never ranked by how safe they are: lists are by date, by name, or best-known first
 *     (the Tranco popularity order the lists are drawn from), never by grade.
 *   - Each named site is a dated measurement ("Measured 13 Nov 2026: classical key exchange"),
 *     with the source of the years, the method, the owner's reply and the opt-out one click away.
 *   - Sector figures are averages; the APIs already leave out every opted-out domain.
 * Same origin only; no inline script or style (widths are set through the CSSOM, as the league
 * page does).
 *
 * How it feels, from real data only. On first view the headline counts up, the A-F bar grows left
 * to right, sector bars fill (and their percentages count) as they scroll into view, and rows come
 * in with a short stagger. While the tab is visible it reads /api/public/stats again every 25 s:
 * a rise in this week's checks rolls the number and shows "+N checks just now", the bar glides to
 * new shares, and the live dot takes one breath per reading (grey when paused: tab hidden, or no
 * reading arrived). A row measured in the last hour pulses once; a change since this visitor's last
 * visit is marked. With prefers-reduced-motion every update is simply there.
 */
(function () {
  "use strict";
  function I() { return window.MorrowIns; }
  var KEEP_MS = 120000;
  var POLL_MS = 25000;
  var SAMPLE = 6;
  var MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  var GRADES = ["A", "B", "C", "D", "E", "F"];

  function $(s) { return document.querySelector(s); }
  function esc(v) { return I().esc(v); }
  function enc(v) { return encodeURIComponent(v); }
  function num(n) { return n == null || isNaN(n) ? "-" : Number(n).toLocaleString("en-GB"); }
  function pct1(x) { return x == null || isNaN(x) ? "-" : (Math.round(x * 1000) / 10).toFixed(1); }
  function when(iso) {
    var d = new Date(iso); if (!iso || isNaN(d)) return "an unknown date";
    return d.getUTCDate() + " " + MONTHS[d.getUTCMonth()] + " " + d.getUTCFullYear();
  }
  function chip(g) { return '<span class="g-chip" data-g="' + esc(g || "") + '">' + esc(g || "-") + "</span>"; }

  /* One answer per URL, kept for two minutes in this tab so going back and forth costs nothing. */
  function load(url) {
    var key = "morrow_board:" + url;
    try {
      var hit = JSON.parse(sessionStorage.getItem(key) || "null");
      if (hit && Date.now() - hit.t < KEEP_MS) return Promise.resolve(hit.v);
    } catch (e) { /* storage blocked: just fetch */ }
    return I().getJSON(url, { timeout: 20000 }).then(function (v) {
      try { sessionStorage.setItem(key, JSON.stringify({ t: Date.now(), v: v })); } catch (e) { /* full or blocked */ }
      return v;
    });
  }

  var S = { sector: "", auto: false, q: "", league: null, ups: null, ready: null, safe: null, timer: 0, seq: 0, sseq: 0,
            box: null, tick: 0, poll: 0, stats: null, since: null, first: true };
  var REDUCED = !!(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches);

  /* A number arriving, eased up from zero (straight to the value under reduced motion). */
  function countUp(el, to, dec, tail) {
    var fmt = function (v) { return v.toFixed(dec) + (tail || ""); };
    if (REDUCED || !window.requestAnimationFrame) { el.innerHTML = fmt(to); return; }
    var t0 = null, D = 650;
    (function step(t) {
      if (t0 == null) t0 = t;
      var k = Math.min(1, (t - t0) / D), e = 1 - Math.pow(1 - k, 3);
      el.innerHTML = fmt(to * e);
      if (k < 1) requestAnimationFrame(step);
    })(performance.now());
  }
  /* A number that changed: only the digits that differ roll in, right to left. */
  function roll(el, text) {
    var old = el.getAttribute("data-v") || el.textContent;
    el.setAttribute("data-v", text);
    if (REDUCED || old === text) { el.textContent = text; return; }
    var off = old.length - text.length, out = "", n = 0;
    for (var i = text.length - 1; i >= 0; i--) {            // compared from the right, as digits line up
      var ch = text.charAt(i), was = old.charAt(i + off);
      out = (ch !== was && /\d/.test(ch) ? '<span class="fb-roll fb-roll-' + Math.min(5, n++) + '">' + esc(ch) + "</span>" : esc(ch)) + out;
    }
    el.innerHTML = out;
  }

  /* Since this visitor's last visit: the previous visit's time, kept on this device only. A new
     visit starts after 30 minutes away, so reloading does not reset it. */
  function lastVisit() {
    var now = Date.now(), v = null;
    try { v = JSON.parse(localStorage.getItem("morrow_board_visit") || "null"); } catch (e) { v = null; }
    if (!v || typeof v.cur !== "number") v = { last: null, cur: now };
    else if (now - v.cur > 30 * 60000) v = { last: v.cur, cur: now };
    else v.cur = now;
    try { localStorage.setItem("morrow_board_visit", JSON.stringify(v)); } catch (e) { /* private mode */ }
    return v.last;
  }

  function skeletonRows(n) {
    var out = "";
    for (var i = 0; i < n; i++) out += '<li class="fb-sk-row" aria-hidden="true"><span class="fb-sk fb-sk-chip"></span><span class="fb-sk fb-sk-line"></span><span class="fb-sk fb-sk-line short"></span></li>';
    return out;
  }
  function skeletonSectors() {
    var out = "";
    for (var i = 0; i < 8; i++) out += '<li class="fb-s fb-s-sk" aria-hidden="true"><span class="fb-sk fb-sk-line short"></span><span class="fb-sk fb-sk-big"></span><span class="fb-sk fb-sk-line"></span></li>';
    return out;
  }
  function column(id, tone, glyph, title) {
    return '<section class="fb-col" data-tone="' + tone + '" aria-labelledby="' + id + '-h" aria-busy="true" id="' + id + '-col">' +
      '<header class="fb-col-h"><span class="fb-ic" aria-hidden="true">' + glyph + '</span><h3 class="fb-h3" id="' + id + '-h">' + esc(title) + '</h3><span class="fb-n" id="' + id + '-n"></span></header>' +
      '<p class="fb-col-k" id="' + id + '-k"></p>' +
      '<ol class="fb-list" id="' + id + '" aria-labelledby="' + id + '-h">' + skeletonRows(4) + "</ol>" +
      '<div class="fb-col-f" id="' + id + '-f"></div></section>';
  }

  function frame() {
    return '<section class="fb" id="board" aria-labelledby="fb-h">' +
      '<div class="fb-top">' +
        '<div class="fb-head">' +
          '<p class="fb-eye"><span class="fb-dot" id="fb-dot" data-live="off" aria-hidden="true"></span>Live board &middot; who is quantum-safe<span class="sr-only" id="fb-live-sr"></span></p>' +
          '<h2 class="fb-h" id="fb-h"><span class="sr-only" id="fb-big-sr"></span><span class="fb-big" id="fb-big"><span class="fb-sk fb-sk-num"></span></span>' +
          '<span class="fb-say" id="fb-say"><span class="fb-sk fb-sk-line"></span><span class="fb-sk fb-sk-line short"></span></span></h2>' +
          '<p class="fb-meta" id="fb-meta"></p>' +
          '<p class="fb-just" id="fb-just" aria-live="polite" hidden></p>' +
          '<p class="fb-since" id="fb-since" hidden></p>' +
        "</div>" +
        '<div class="fb-dist" id="fb-dist" aria-busy="true"><p class="fb-k">Grades this week, A to F</p><span class="bar fb-bar"></span><ol class="fb-legend" id="fb-legend"></ol></div>' +
      "</div>" +
      '<div class="fb-block">' +
        '<div class="fb-block-h"><h3 class="fb-h3" id="fb-sec-h">By sector</h3><p class="fb-note">Share of each sector&rsquo;s well-known sites with a quantum-safe key exchange. Averages; choose a sector to see its sites below.</p></div>' +
        '<ul class="fb-sec" id="fb-sec" aria-labelledby="fb-sec-h" aria-busy="true">' + skeletonSectors() + "</ul>" +
      "</div>" +
      '<div class="fb-block fb-find">' +
        '<div class="fb-find-row"><label class="fb-k" for="fb-q">Find a company in these lists</label><span class="fb-filter" id="fb-filter"></span></div>' +
        '<div class="i-field fb-field"><span class="p" aria-hidden="true">&rsaquo;</span><input type="search" id="fb-q" autocomplete="off" autocapitalize="none" spellcheck="false" inputmode="search" placeholder="A company or domain, like adyen" aria-describedby="fb-status"></div>' +
        '<p class="fb-status" id="fb-status" aria-live="polite"></p>' +
      "</div>" +
      '<div class="fb-cols" id="fb-cols">' +
        column("fb-up", "ok", "&uarr;", "Just became quantum-safe") +
        column("fb-not", "warn", "&#9675;", "Not yet post-quantum") +
      "</div>" +
      '<div id="fb-ready-slot"></div>' +
      '<div class="fb-foot"><p class="fb-rules">Not a ranking: sites are listed by date, by name or best-known first (the popularity order of the Tranco list they come from), never by grade. Each line is one dated measurement of the site&rsquo;s TLS key exchange, ' +
        'made the same way for every site (<a href="/about-scanner">how Morrow checks</a>). Owners can <a href="/league#nr-correct">reply or ask for a correction</a>, and any domain can be ' +
        '<a href="/abuse">opted out</a>; an opted-out domain is never shown.</p>' +
      '<nav class="fb-links" aria-label="Public lists"><a href="/league">League</a><a href="/report">Sector reports</a><a href="/changes">What changed</a>' +
        '<a href="/api/public/changes.rss">RSS</a><a href="/threat">Threat board</a><a href="/vendors">Check your vendors</a></nav></div>' +
      "</section>";
  }

  /* ── the headline number, the A-F bar, and the live reading ── */
  function paintStats(s) {
    var by = I().byDepth;
    var total = s.public_checks_7d;
    var big = $("#fb-big");
    S.stats = s;
    if (total) {
      big.setAttribute("aria-hidden", "true"); $("#fb-big-sr").textContent = pct1(s.pq_share_7d) + "% ";
      var seen = false;
      try { seen = sessionStorage.getItem("morrow_board_counted") === "1"; sessionStorage.setItem("morrow_board_counted", "1"); } catch (e) { seen = false; }
      if (seen) big.innerHTML = pct1(s.pq_share_7d) + "<small>%</small>"; else countUp(big, Math.round((s.pq_share_7d || 0) * 1000) / 10, 1, "<small>%</small>");
    } else big.innerHTML = "&ndash;";
    var checks = '<span class="fb-num" id="fb-checks" data-v="' + esc(num(total)) + '">' + esc(num(total)) + "</span>";
    $("#fb-say").innerHTML = !total ? "No public checks have been made on this server in the last 7 days yet." : by({
      plain: "of the " + checks + " website checks this week found a quantum-safe connection.",
      standard: "of this week&rsquo;s " + checks + " checks found a quantum-safe key exchange.",
      expert: "of " + checks + " checks in 7 days negotiated a post-quantum hybrid key exchange (rubric " + esc(s.rubric_version || "-") + ")."
    });
    $("#fb-meta").innerHTML = '<span class="fb-tick">' + esc(num(s.domains_checked)) + " different sites checked in all</span>" +
      '<span class="fb-tick">counted <time id="fb-ago" datetime="' + esc(s.generated_at || "") + '">' + esc(I().ago(s.generated_at) || "just now") + "</time></span>" +
      '<a class="fb-tick" href="/report">method</a>';
    paintDist(s);
    clearInterval(S.tick);
    S.tick = setInterval(function () { var t = $("#fb-ago"); if (!t) { clearInterval(S.tick); return; } t.textContent = I().ago(S.stats && S.stats.generated_at) || "just now"; }, 15000);
  }
  function paintDist(s) {
    var g = s.grades_7d || {}, sum = 0;
    GRADES.forEach(function (k) { sum += g[k] || 0; });
    var dist = $("#fb-dist");
    if (!sum) { dist.innerHTML = '<p class="fb-k">Grades this week, A to F</p><p class="fb-empty">No grades in the last 7 days yet.</p>'; dist.removeAttribute("aria-busy"); return; }
    dist.innerHTML = '<p class="fb-k" id="fb-dist-k">Grades this week, A to F</p>' +
      '<span class="bar fb-bar" id="fb-bar" role="img" aria-labelledby="fb-dist-k" aria-describedby="fb-legend">' + GRADES.map(function (k) {
        return '<i class="seg" data-g="' + k + '" data-w="' + ((g[k] || 0) / sum) + '"></i>';
      }).join("") + "</span>" +
      '<ol class="fb-legend" id="fb-legend">' + GRADES.map(function (k) {
        return "<li>" + chip(k) + '<span class="fb-legend-n" data-g="' + k + '">' + num(g[k] || 0) + "</span></li>";
      }).join("") + "</ol>" +
      '<p class="fb-key"><span><b>A, B</b> post-quantum key exchange</span><span><b>C to F</b> classical, or a certificate or protocol to fix</span></p>';
    dist.removeAttribute("aria-busy");
    widths(dist);
  }
  /* A later reading: the numbers that moved roll, the bar glides, nothing is redrawn. */
  function update(s) {
    var was = S.stats || {};
    S.stats = s;
    var rise = (s.public_checks_7d || 0) - (was.public_checks_7d || 0);
    var c = $("#fb-checks"); if (c) roll(c, num(s.public_checks_7d));
    var big = $("#fb-big");
    if (big && s.pq_share_7d !== was.pq_share_7d) { big.innerHTML = pct1(s.pq_share_7d) + "<small>%</small>"; $("#fb-big-sr").textContent = pct1(s.pq_share_7d) + "% "; }
    var g = s.grades_7d || {}, sum = 0;
    GRADES.forEach(function (k) { sum += g[k] || 0; });
    var bar = $("#fb-bar");
    if (bar && sum) {
      bar.classList.add("fb-bar-live");
      Array.prototype.forEach.call(bar.querySelectorAll(".seg"), function (el) {
        var w = (g[el.getAttribute("data-g")] || 0) / sum;
        el.setAttribute("data-w", w); el.style.width = (w * 100).toFixed(2) + "%";
      });
      Array.prototype.forEach.call(document.querySelectorAll("#fb-legend .fb-legend-n"), function (el) { roll(el, num(g[el.getAttribute("data-g")] || 0)); });
    }
    var t = $("#fb-ago"); if (t) t.textContent = I().ago(s.generated_at) || "just now";
    if (rise > 0) {
      var j = $("#fb-just");
      j.innerHTML = '<span class="fb-plus">+' + num(rise) + " check" + (rise === 1 ? "" : "s") + "</span> just now";
      j.hidden = false; j.classList.remove("fb-flash"); void j.offsetWidth; j.classList.add("fb-flash");
      clearTimeout(S.justT); S.justT = setTimeout(function () { j.hidden = true; }, REDUCED ? 8000 : 4200);
    }
  }
  function live(on) {
    var d = $("#fb-dot"); if (!d) return;
    d.setAttribute("data-live", on ? "on" : "off");
    var sr = $("#fb-live-sr"); if (sr) sr.textContent = on ? ", reading live" : ", paused";
    if (on && !REDUCED) { d.classList.remove("fb-beat"); void d.offsetWidth; d.classList.add("fb-beat"); }
  }
  /* Read again every POLL_MS while the tab is visible; stop when hidden, resume (at once) when shown. */
  function startPolling() {
    clearInterval(S.poll);
    // On the front page's story the page already reads the counts every 25 s (home-story.js): the
    // board takes each of those readings instead of asking again.
    if (window.MorrowHome && window.MorrowHome.onStats) {
      if (!S.shared) { S.shared = true; window.MorrowHome.onStats(function (s) { if (document.getElementById("board")) { update(s); live(true); } }); }
      return;
    }
    var read = function () {
      if (document.hidden || !document.getElementById("board")) return;
      I().getJSON("/api/public/stats", { cache: "no-store", timeout: 15000 })
        .then(function (s) { update(s); live(true); })
        .catch(function () { live(false); });
    };
    S.poll = setInterval(function () { if (!document.getElementById("board")) { clearInterval(S.poll); return; } read(); }, POLL_MS);
    if (!S.visBound) {
      S.visBound = true;
      document.addEventListener("visibilitychange", function () { if (document.hidden) live(false); else if (S.stats) read(); });
    }
  }
  /* Bars take their measured width when they scroll into view (and sector percentages count with them). */
  function widths(root) {
    var set = function (el) { el.style.width = (Math.max(0, Math.min(1, Number(el.getAttribute("data-w")))) * 100).toFixed(2) + "%"; };
    var pcts = function (r) { Array.prototype.forEach.call(r.querySelectorAll(".fb-s-pct[data-v]"), function (el) { countUp(el, Number(el.getAttribute("data-v")), 1, "<small>%</small>"); el.removeAttribute("data-v"); }); };
    var els = Array.prototype.slice.call(root.querySelectorAll("[data-w]"));
    if (REDUCED || !window.IntersectionObserver) { els.forEach(set); pcts(root); return; }
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        if (!en.isIntersecting) return;
        Array.prototype.forEach.call(en.target.querySelectorAll("[data-w]"), set);
        pcts(en.target);
        io.unobserve(en.target);
      });
    }, { threshold: 0.2 });
    io.observe(root);
  }

  /* ── the sector board ── */
  function spark(trend) {
    if (!trend || trend.length < 2) return "";
    var w = 64, h = 18, n = trend.length;
    var pts = trend.map(function (t, i) { return (i * (w - 2) / (n - 1) + 1).toFixed(1) + "," + (h - 1 - (t.pq_share || 0) * (h - 2)).toFixed(1); }).join(" ");
    return '<svg class="fb-spark" viewBox="0 0 ' + w + " " + h + '" preserveAspectRatio="none" aria-hidden="true" focusable="false"><polyline pathLength="1" points="' + pts + '"/></svg>';
  }
  function trendWords(trend) {
    if (!trend || !trend.length) return { t: "", sr: "" };
    if (trend.length < 2) { var w0 = "measured since " + when(trend[0].week).replace(/ \d{4}$/, ""); return { t: w0, sr: w0 + ", one week so far" }; }
    var a = trend[0], b = trend[trend.length - 1], d = Math.round(((b.pq_share || 0) - (a.pq_share || 0)) * 1000) / 10;
    var since = when(a.week).replace(/ \d{4}$/, "");
    if (!d) return { t: "no change since " + since, sr: "no change since " + since, dir: "flat" };
    return { t: (d > 0 ? "▲ " : "▼ ") + Math.abs(d).toFixed(1) + " pts since " + since,
      sr: (d > 0 ? "up " : "down ") + Math.abs(d).toFixed(1) + " points since " + since, dir: d > 0 ? "up" : "down" };
  }
  function sectors() { return ((S.league && S.league.sectors) || []).filter(function (s) { return s.graded; }).slice().sort(function (a, b) { return String(a.name).localeCompare(String(b.name)); }); }
  function paintSectors(L) {
    S.league = L;
    var box = $("#fb-sec");
    var list = sectors();
    box.removeAttribute("aria-busy");
    if (!list.length) { box.innerHTML = '<li class="fb-empty">No sector has graded sites on this server yet. The sector lists are re-graded weekly, a few sites at a time.</li>'; return; }
    box.innerHTML = list.map(function (s) {
      var tw = trendWords(s.trend);
      return '<li class="fb-s"><button type="button" class="fb-s-b" data-s="' + esc(s.id) + '" aria-pressed="' + (S.sector === s.id) + '">' +
        '<span class="fb-s-name">' + esc(s.name) + "</span>" +
        '<span class="fb-s-pct"' + (REDUCED ? "" : ' data-v="' + pct1(s.pq_share) + '"') + ">" + (REDUCED ? pct1(s.pq_share) : "0.0") + "<small>%</small></span>" +
        '<span class="fb-s-bar" aria-hidden="true"><i data-w="' + (s.pq_share || 0) + '"></i></span>' +
        '<span class="fb-s-low"><span class="fb-s-foot"><span class="fb-s-tr" data-dir="' + (tw.dir || "") + '" aria-hidden="true">' + spark(s.trend) + esc(tw.t) + "</span>" +
        '<span class="fb-s-n" aria-hidden="true">' + num(s.graded) + " sites</span></span>" +
        '<span class="fb-s-alt" aria-hidden="true">' + GRADES.map(function (k) { var n = (s.grades || {})[k] || 0; return '<span class="fb-s-g" data-g="' + k + '"><b>' + k + "</b>" + n + "</span>"; }).join("") + "</span></span>" +
        '<span class="sr-only">: ' + pct1(s.pq_share) + " percent of " + num(s.graded) + " graded sites use a quantum-safe key exchange, " + esc(tw.sr) + ". Show this sector&rsquo;s sites below.</span>" +
        '</button><a class="fb-s-r" href="/report/' + enc(s.id) + '">Report<span class="sr-only"> on ' + esc(s.name) + "</span> &rarr;</a></li>";
    }).join("");
    widths(box);
    box.addEventListener("click", function (e) {
      var b = e.target.closest("button[data-s]"); if (!b) return;
      pick(S.sector === b.getAttribute("data-s") && !S.auto ? "" : b.getAttribute("data-s"), false);
    });
    filterLine();
  }
  function sectorName(id) {
    var hit = ((S.league && S.league.sectors) || []).filter(function (s) { return s.id === id; })[0];
    return hit ? hit.name : id;
  }
  /* A sector for this visit, chosen here at random so each visit opens on a different part of the
     board; "Another sector" moves on. The URL only records a sector the visitor chose. */
  function randomSector() {
    var list = sectors(); if (!list.length) return "";
    return list[Math.floor(Math.random() * list.length)].id;
  }
  function nextSector() {
    var list = sectors(); if (!list.length) return;
    var i = 0; list.forEach(function (s, k) { if (s.id === S.sector) i = k + 1; });
    pick(list[i % list.length].id, true);
  }
  function pick(id, auto) {
    S.sector = id; S.auto = !!auto && !!id;
    I().setParam("sector", id && !auto ? id : null);
    Array.prototype.forEach.call(document.querySelectorAll("#fb-sec button[data-s]"), function (b) { b.setAttribute("aria-pressed", String(b.getAttribute("data-s") === id)); });
    filterLine();
    swap(function () { paintUps(); paintReady(); paintNot(); });
  }
  /* Rows cross-fade when the sector changes: the old ones fade, the new ones come in staggered. */
  function swap(paint) {
    var lists = Array.prototype.slice.call(document.querySelectorAll("#fb-cols .fb-list"));
    if (REDUCED || !lists.length) { paint(); return; }
    lists.forEach(function (l) { l.classList.add("fb-out"); });
    setTimeout(function () { lists.forEach(function (l) { l.classList.remove("fb-out"); }); paint(); }, 140);
  }
  function filterLine() {
    var f = $("#fb-filter"); if (!f) return;
    f.innerHTML = S.sector ? "Sector: <b>" + esc(sectorName(S.sector)) + "</b>" + (S.auto ? ' <span class="fb-dim">(picked for this visit)</span>' : "") +
      ' <button type="button" class="fb-clear" id="fb-next">Another sector</button> <button type="button" class="fb-clear" id="fb-clear">All sectors</button>' : "All sectors";
    var c = $("#fb-clear"); if (c) c.addEventListener("click", function () { pick("", false); var q = $("#fb-q"); if (q) q.focus(); });
    var n = $("#fb-next"); if (n) n.addEventListener("click", nextSector);
  }

  /* ── the named lists ── */
  /* The sector the lists show: a search looks everywhere unless the visitor chose the sector. */
  function sectorNow() { return S.q && S.auto ? "" : S.sector; }
  function matches(e) {
    var sec = sectorNow();
    return (!sec || e.sector === sec) && (!S.q || String(e.domain).indexOf(S.q) >= 0);
  }
  function setCount(id, text) { var n = $("#" + id + "-n"); if (n) n.textContent = text; }
  function setHead(id, title, k) { var h = $("#" + id + "-h"); if (h) h.textContent = title; var p = $("#" + id + "-k"); if (p) p.innerHTML = k || ""; }
  function glyph(id, g) { var i = $("#" + id + "-col .fb-ic"); if (i) i.innerHTML = g; }
  function done(id) { var c = $("#" + id + "-col"); if (c) c.removeAttribute("aria-busy"); }
  function unavailable(id, what, e) {
    var l = $("#" + id); if (!l) return;
    l.innerHTML = '<li class="fb-empty">' + esc(what) + " could not be read just now" + (e && e.status ? " (HTTP " + e.status + ")" : "") + ". The domain box above still works.</li>";
    setCount(id, ""); done(id);
  }
  function recent(iso) { var t = Date.parse(iso); return !isNaN(t) && Date.now() - t < 3600000; }
  /* One named row. ``more`` is revealed on hover or focus; ``isNew`` marks a change since the last
     visit; a row measured in the last hour pulses once. */
  function item(href, g, prev, domain, words, extra, more, isNew, at) {
    return '<li class="fb-row' + (isNew ? " fb-fresh" : "") + (recent(at) ? " fb-recent" : "") + '"><a class="fb-item" href="' + href + '">' +
      '<span class="fb-g">' + (prev ? chip(prev) + '<span class="fb-to" aria-label="to">&rarr;</span>' : "") + chip(g) + "</span>" +
      '<span class="fb-d">' + esc(domain) + (isNew ? ' <span class="fb-new">new since your last visit</span>' : "") + (recent(at) ? ' <span class="fb-new fb-hour">measured in the last hour</span>' : "") + "</span>" +
      '<span class="fb-w">' + words + "</span>" + (more ? '<span class="fb-x">' + more + ' <span aria-hidden="true">&rarr;</span></span>' : "") + "</a>" + (extra || "") + "</li>";
  }
  function replyHtml(r) {
    return r ? '<p class="fb-reply"><span class="fb-k">Owner&rsquo;s reply, ' + esc(when(r.at)) + "</span> &ldquo;" + esc(r.text) + "&rdquo;</p>" : "";
  }
  function inSector() { var s = sectorNow(); return s ? " in " + esc(sectorName(s)) : ""; }

  function fresh(e) { return S.since && Date.parse(e.at) > S.since; }
  function sinceLine() {
    var el = $("#fb-since"); if (!el || !S.ups || !S.since) return;
    var ev = S.ups.events || [], up = 0, down = 0;
    ev.forEach(function (e) {
      if (!fresh(e)) return;
      if (e.kind === "ready" || e.kind === "listed") up++; else if (e.kind === "not_ready") down++;
      else if (e.kind === "sector") { up += e.became_ready || 0; down += e.dropped || 0; }
    });
    var on = when(new Date(S.since).toISOString());
    el.innerHTML = '<span class="fb-since-k">Since your last visit, ' + esc(on) + "</span> " + (up || down
      ? (up ? '<b class="fb-up">' + num(up) + " site" + (up === 1 ? "" : "s") + " became quantum-safe</b>" : "") + (up && down ? ", " : "") +
        (down ? num(down) + " moved below B" : "") + '. <a href="/changes">What changed</a>'
      : "Nothing on these lists crossed B. The weekly re-checks keep running.");
    el.hidden = false;
  }
  /* The first column: sites that just became quantum-safe; while there are none for this view, the
     well-known sites whose newest check this week is A or B (GET /api/public/checked-safe). */
  function paintUps() {
    if (!S.ups) return;
    sinceLine();
    var rows = (S.ups.events || []).filter(function (e) { return e.kind === "ready" && e.named && e.domain; }).filter(matches);
    if (!rows.length) { paintSafe(); return; }
    setHead("fb-up", "Just became quantum-safe", "Newest change first."); glyph("fb-up", "&uarr;");
    setCount("fb-up", num(rows.length) + (rows.length > SAMPLE ? " · newest " + SAMPLE : ""));
    $("#fb-up").innerHTML = rows.slice(0, SAMPLE).map(function (e) {
      var kx = e.group ? "post-quantum key exchange (" + esc(e.group) + ")" : "graded " + esc(e.grade);
      return item("/r/" + enc(e.domain), e.grade, e.previous_grade, e.domain, "Measured " + esc(when(e.at)) + ": " + kx, replyHtml(e.reply),
        esc(e.sector_name || "") + " &middot; open its record", fresh(e), e.at);
    }).join("");
    $("#fb-up-f").innerHTML = '<a href="/changes">Everything that changed</a><a href="/api/public/changes.rss">RSS</a><a href="/api/public/changes.atom">Atom</a>';
    done("fb-up");
  }
  function paintSafe() {
    var seq = ++S.sseq, sec = sectorNow();
    setHead("fb-up", "Checked this week: quantum-safe", "Well-known sites, best-known first, newest check of each."); glyph("fb-up", "&check;");
    var col = $("#fb-up-col"); if (col) col.setAttribute("aria-busy", "true");
    load("/api/public/checked-safe?order=popular&days=8&limit=" + SAMPLE + (sec ? "&sector=" + enc(sec) : "") + (S.q ? "&q=" + enc(S.q) : "")).then(function (Q) {
      if (seq !== S.sseq) return;
      S.safe = Q;
      var list = (Q.entries || []).filter(matches);
      setCount("fb-up", S.q ? num(Q.matched || 0) + " match" + (Q.matched === 1 ? "" : "es") : num(Q.count || 0) + " sites");
      $("#fb-up").innerHTML = list.length ? list.slice(0, SAMPLE).map(function (e) {
        var kx = e.key_exchange ? "post-quantum key exchange (" + esc(e.key_exchange) + ")" : "graded " + esc(e.grade);
        return item("/r/" + enc(e.domain), e.grade, null, e.domain, "Measured " + esc(when(e.checked_at)) + ": " + kx, "",
          esc(e.sector_name || "") + " &middot; open its record", false, e.checked_at);
      }).join("") : '<li class="fb-empty">' + (S.q ? "No well-known site matching &ldquo;" + esc(S.q) + "&rdquo;" + inSector() + " was graded A or B this week."
        : "No well-known site" + inSector() + " was graded A or B in the last 8 days. The weekly re-checks keep running.") + "</li>";
      $("#fb-up-f").innerHTML = "<span>By popularity on the Tranco list, never by grade. Nothing just became quantum-safe" + inSector() + ' yet; when a re-check finds one, it shows here first.</span><a href="/changes">What changed</a><a href="/api/public/changes.rss">RSS</a>';
      done("fb-up");
      searchLine();
    }).catch(function (e) { if (seq === S.sseq) unavailable("fb-up", "The quantum-safe list", e); });
  }
  /* Verified ready: a column once someone has listed themselves; until then a slim invitation. */
  function paintReady() {
    if (!S.ready) return;
    var all = S.ready.entries || [], slot = $("#fb-ready-slot"), cols = $("#fb-cols");
    if (!all.length) {
      var old = $("#fb-ready-col"); if (old) old.parentNode.removeChild(old);
      if (cols) cols.classList.remove("fb-cols-3");
      slot.innerHTML = '<aside class="fb-strip" aria-labelledby="fb-strip-h"><span class="fb-ic" aria-hidden="true">&check;</span><p><b id="fb-strip-h">Verified ready: no organisation has listed itself yet.</b> ' +
        'Own a domain that grades A or B? Check it above, choose <i>Claim it</i> on its record, and list it here once it is verified.</p>' +
        '<a class="i-btn" href="#home-q" id="fb-claim">Check your domain</a></aside>';
      var c = $("#fb-claim");
      if (c) c.addEventListener("click", function (e) { var q = document.getElementById("home-q"); if (q) { e.preventDefault(); q.focus(); q.scrollIntoView({ block: "center" }); } });
      return;
    }
    slot.innerHTML = "";
    if (!$("#fb-ready-col")) { cols.insertAdjacentHTML("beforeend", column("fb-ready", "ok", "&check;", "Verified ready")); cols.classList.add("fb-cols-3"); }
    var rows = all.filter(matches);
    setHead("fb-ready", "Verified ready", "Owners who verified their domain and chose to be listed. By name.");
    setCount("fb-ready", rows.length ? num(rows.length) + " listed" : "");
    $("#fb-ready").innerHTML = rows.length ? rows.slice(0, SAMPLE).map(function (e) {
      return item("/r/" + enc(e.domain), e.grade, null, e.domain, "Owner verified &middot; measured " + esc(when(e.checked_at)) + " &middot; listed since " + esc(when(e.joined_at)), "",
        esc(e.sector_name || "") + " &middot; open its record", false, e.checked_at);
    }).join("") : '<li class="fb-empty">No verified site' + inSector() + (S.q ? " matches &ldquo;" + esc(S.q) + "&rdquo;" : "") + ".</li>";
    $("#fb-ready-f").innerHTML = '<span>Re-checked weekly; leaves below B.</span><a href="/api/public/pq-ready.atom">Atom</a>';
    done("fb-ready");
  }
  function notWords(e) {
    var st = String(e.statement || "");
    var words = e.key_exchange ? "classical key exchange (" + esc(e.key_exchange) + ")" : "key exchange not observed";
    if (/certificate did not verify/i.test(st)) words += ", certificate did not verify";
    if (/TLS 1\.0 or 1\.1/.test(st)) words += ", TLS 1.0 or 1.1 accepted";
    return "Measured " + esc(when(e.checked_at)) + ": " + words;
  }
  function paintNot() {
    var seq = ++S.seq, sec = sectorNow();
    var url = "/api/public/not-ready?order=popular&limit=" + SAMPLE + (sec ? "&sector=" + enc(sec) : "") + (S.q ? "&q=" + enc(S.q) : "");
    var col = $("#fb-not-col"); if (col) col.setAttribute("aria-busy", "true");
    setHead("fb-not", "Not yet post-quantum", "Well-known sites, best-known first, newest check of each.");
    load(url).then(function (N) {
      if (seq !== S.seq) return;
      S.not = N;
      var list = (N.entries || []).filter(matches);   // an older server answers the whole list; filter here too
      var total = N.count || 0, matched = N.matched != null ? N.matched : list.length;
      setCount("fb-not", S.q ? num(matched) + " match" + (matched === 1 ? "" : "es") : num(total) + " sites");
      $("#fb-not").innerHTML = list.length ? list.slice(0, SAMPLE).map(function (e) {
        return item("/r/" + enc(e.domain), e.grade, null, e.domain, notWords(e), replyHtml(e.reply),
          esc(e.sector_name || "") + (e.decrypt_year_low ? " &middot; recorded traffic readable from about " + esc(e.decrypt_year_low) : "") + " &middot; open its record", false, e.checked_at);
      }).join("") : '<li class="fb-empty">' + (S.q ? "No listed site matches &ldquo;" + esc(S.q) + "&rdquo;" + inSector() + "."
        : "No site from the popular-sites list is below B on this server" + inSector() + ".") + "</li>";
      var m = N.methodology || {}, w = m.decrypt_window || {};
      var all = "/league" + (sec ? "?nr=" + enc(sec) : "");
      $("#fb-not-f").innerHTML = '<a class="fb-all" href="' + all + '">See all ' + num(total) + inSector() + " &rarr;</a>" +
        "<span>By popularity on the Tranco list, never by grade. Years " + esc(w.low || 2035) + "&ndash;" + esc(w.high || 2040) + ' from <a href="' + esc(w.source_url || "/report") + '" rel="noopener">' + esc(w.source || "the cited source") + "</a>.</span>";
      done("fb-not");
      searchLine();
    }).catch(function (e) { if (seq === S.seq) { S.not = null; unavailable("fb-not", "The not-yet-post-quantum list", e); searchLine(); } });
  }
  function searchLine() {
    var st = $("#fb-status"); if (!st) return;
    if (!S.q) { st.innerHTML = ""; return; }
    var ups = S.ups ? (S.ups.events || []).filter(function (e) { return e.kind === "ready" && e.named && matches(e); }).length : 0;
    var ready = S.ready ? (S.ready.entries || []).filter(matches).length : 0;
    var safe = S.safe && S.safe.query === S.q ? S.safe.matched || 0 : 0;
    var not = S.not && S.not.query === S.q ? S.not.matched || 0 : 0;
    var n = ups + ready + safe + not;
    var d = I().asDomain(S.q);
    var liveLink = d ? ' <a href="/r/' + enc(d) + '">Check ' + esc(d) + " live &rarr;</a>" : " Type the full domain, like example.com, to check it live.";
    st.innerHTML = n ? num(n) + " listed site" + (n === 1 ? "" : "s") + " match &ldquo;" + esc(S.q) + "&rdquo;." + (d ? liveLink : "")
      : "&ldquo;" + esc(S.q) + "&rdquo; is not in these lists" + inSector() + "." + liveLink;
  }

  function mount(box) {
    if (!box) return;
    S.box = box;
    if (S.since === null) S.since = lastVisit() || 0;
    var chosen = (I().param && I().param("sector")) || "";
    if (!/^[a-z0-9-]{1,40}$/.test(chosen)) chosen = "";
    S.sector = chosen; S.auto = false;
    box.innerHTML = frame();
    filterLine();
    var q = $("#fb-q");
    q.addEventListener("input", function () {
      clearTimeout(S.timer);
      S.timer = setTimeout(function () {
        var v = q.value.trim().toLowerCase().replace(/^[a-z][a-z0-9+.-]*:\/\//, "").replace(/^www\./, "").split(/[/?#\s]/)[0].slice(0, 80);
        if (v === S.q) return;
        S.q = v; paintUps(); paintReady(); paintNot();
      }, 220);
    });
    // After the page has painted, read everything at once; each part paints when its answer lands.
    // The named lists wait only for the sectors, to open on this visit's sector.
    var go = function () {
      load("/api/public/stats").then(function (s) { paintStats(s); live(true); startPolling(); }).catch(function (e) {
        $("#fb-big").innerHTML = ""; $("#fb-h").classList.add("fb-h-off");
        $("#fb-say").textContent = "This week’s counts could not be read just now" + (e && e.status ? " (HTTP " + e.status + ")" : "") + ". The domain box above still works.";
        $("#fb-dist").innerHTML = ""; $("#fb-dist").removeAttribute("aria-busy");
        live(false);
      });
      var ups = load("/api/public/changes?limit=100").then(function (C) { S.ups = C; }).catch(function (e) { S.upsErr = e; });
      load("/api/public/pq-ready").then(function (Q) { S.ready = Q; paintReady(); }).catch(function () { S.ready = { entries: [] }; paintReady(); });
      load("/api/public/league").then(function (L) {
        paintSectors(L);
        if (!S.sector) { S.sector = randomSector(); S.auto = !!S.sector; }
        Array.prototype.forEach.call(document.querySelectorAll("#fb-sec button[data-s]"), function (b) { b.setAttribute("aria-pressed", String(b.getAttribute("data-s") === S.sector)); });
        filterLine();
      }).catch(function (e) {
        var b = $("#fb-sec"); b.removeAttribute("aria-busy");
        b.innerHTML = '<li class="fb-empty">The sector averages could not be read just now' + (e && e.status ? " (HTTP " + e.status + ")" : "") + '. <a href="/league">Open the league</a>.</li>';
      }).then(function () {
        paintNot();
        ups.then(function () { if (S.ups) paintUps(); else unavailable("fb-up", "The change feed", S.upsErr); });
      });
    };
    if (window.requestAnimationFrame) requestAnimationFrame(function () { setTimeout(go, 0); }); else setTimeout(go, 0);
  }

  /* "yourdomain.com is still B": the last domain this visitor checked here (on this device), with
     its two newest stored checks. Read-only: /api/public/history never runs a check. */
  function welcomeBack(el) {
    if (!el) return;
    var d = "";
    try { var r = JSON.parse(localStorage.getItem("morrow_recent") || "[]").filter(function (x) { return x && x.kind === "domain"; })[0]; d = r && I().asDomain(r.id) || ""; } catch (e) { d = ""; }
    if (!d) return;
    I().getJSON("/api/public/history/" + enc(d) + "?limit=2", { timeout: 15000 }).then(function (h) {
      if (!h || !h.length || !h[0].grade) return;
      var now = h[0], before = h[1];
      var moved = before && before.grade && before.grade !== now.grade;
      el.innerHTML = '<a href="/r/' + enc(d) + '"><b>' + esc(d) + "</b> " + (moved ? "moved from " + esc(before.grade) + " to " + esc(now.grade) : "is still " + esc(now.grade)) +
        " (checked " + esc(when(now.scanned_at)) + "): " + (moved ? "see what changed" : "see its record") + " &rarr;</a>";
      el.setAttribute("data-g", now.grade);
      el.hidden = false;
    }).catch(function () { /* nothing to say */ });
  }

  window.MorrowBoard = { mount: mount, welcomeBack: welcomeBack };
})();
