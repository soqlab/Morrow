/*
 * The front page's live board: who is quantum-safe (instrument.js calls MorrowBoard.mount()).
 *
 * Under the domain box on "/". Everything on it is public and needs no account: it reads only
 * /api/public/stats, /league, /changes, /pq-ready and /not-ready, after the page has painted, in
 * parallel, and keeps each answer for two minutes in this tab (sessionStorage). The domain box
 * works whether or not any of it arrives; each part says plainly what is missing when it does not.
 *
 * What it keeps from the league page (services/not_ready.py, services/changes.py, pq_ready.py):
 *   - Sites are never ranked against each other: lists are by date or by name, never by grade.
 *   - Each named site is a dated measurement ("Measured 13 Nov 2026: classical key exchange"),
 *     with the source of the years, the method, the owner's reply and the opt-out one click away.
 *   - Sector figures are averages; the APIs already leave out every opted-out domain.
 * Same origin only; no inline script or style (bar widths are set through the CSSOM, as the
 * league page does).
 */
(function () {
  "use strict";
  function I() { return window.MorrowIns; }
  var KEEP_MS = 120000;
  var SAMPLE = 6;
  var MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

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

  var S = { sector: "", q: "", league: null, ups: null, ready: null, timer: 0, seq: 0, box: null };

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
  function column(id, tone, glyph, title, foot) {
    return '<section class="fb-col" data-tone="' + tone + '" aria-labelledby="' + id + '-h" aria-busy="true" id="' + id + '-col">' +
      '<header class="fb-col-h"><span class="fb-ic" aria-hidden="true">' + glyph + '</span><h3 class="fb-h3" id="' + id + '-h">' + esc(title) + '</h3><span class="fb-n" id="' + id + '-n"></span></header>' +
      '<ol class="fb-list" id="' + id + '" aria-labelledby="' + id + '-h">' + skeletonRows(4) + "</ol>" +
      '<div class="fb-col-f" id="' + id + '-f">' + (foot || "") + "</div></section>";
  }

  function frame() {
    return '<section class="fb" id="board" aria-labelledby="fb-h">' +
      '<div class="fb-top">' +
        '<div class="fb-head">' +
          '<p class="fb-eye"><span class="fb-dot" aria-hidden="true"></span>Live board &middot; who is quantum-safe</p>' +
          '<h2 class="fb-h" id="fb-h"><span class="fb-big" id="fb-big"><span class="fb-sk fb-sk-num"></span></span>' +
          '<span class="fb-say" id="fb-say"><span class="fb-sk fb-sk-line"></span><span class="fb-sk fb-sk-line short"></span></span></h2>' +
          '<p class="fb-meta" id="fb-meta"></p>' +
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
      '<div class="fb-cols">' +
        column("fb-up", "ok", "&uarr;", "Just became quantum-safe") +
        column("fb-ready", "ok", "&check;", "Verified ready") +
        column("fb-not", "warn", "&#9675;", "Not yet post-quantum") +
      "</div>" +
      '<div class="fb-foot"><p class="fb-rules">Not a ranking: sites are listed by date or by name, never by grade. Each line is one dated measurement of the site&rsquo;s TLS key exchange, ' +
        'made the same way for every site (<a href="/about-scanner">how Morrow checks</a>). Owners can <a href="/league#nr-correct">reply or ask for a correction</a>, and any domain can be ' +
        '<a href="/abuse">opted out</a>; an opted-out domain is never shown.</p>' +
      '<nav class="fb-links" aria-label="Public lists"><a href="/league">League</a><a href="/report">Sector reports</a><a href="/changes">What changed</a>' +
        '<a href="/api/public/changes.rss">RSS</a><a href="/threat">Threat board</a><a href="/vendors">Check your vendors</a></nav></div>' +
      "</section>";
  }

  /* ── the headline number and the A-F bar ── */
  function paintStats(s) {
    var by = I().byDepth;
    var total = s.public_checks_7d;
    $("#fb-big").innerHTML = total ? pct1(s.pq_share_7d) + '<small>%</small>' : "&ndash;";
    $("#fb-say").textContent = !total ? "No public checks have been made on this server in the last 7 days yet." : by({
      plain: "of the " + num(total) + " website checks this week found a quantum-safe connection.",
      standard: "of this week’s " + num(total) + " checks found a quantum-safe key exchange.",
      expert: "of " + num(total) + " checks in 7 days negotiated a post-quantum hybrid key exchange (rubric " + (s.rubric_version || "-") + ")."
    });
    $("#fb-meta").innerHTML = '<span class="fb-tick">' + esc(num(s.domains_checked)) + " different sites checked in all</span>" +
      '<span class="fb-tick">counted <time datetime="' + esc(s.generated_at || "") + '">' + esc(I().ago(s.generated_at) || "just now") + "</time></span>" +
      '<a class="fb-tick" href="/report">method</a>';
    var g = s.grades_7d || {}, sum = 0;
    ["A", "B", "C", "D", "E", "F"].forEach(function (k) { sum += g[k] || 0; });
    var dist = $("#fb-dist");
    if (!sum) { dist.innerHTML = '<p class="fb-k">Grades this week, A to F</p><p class="fb-empty">No grades in the last 7 days yet.</p>'; dist.removeAttribute("aria-busy"); return; }
    dist.innerHTML = '<p class="fb-k" id="fb-dist-k">Grades this week, A to F</p>' +
      '<span class="bar fb-bar" role="img" aria-labelledby="fb-dist-k" aria-describedby="fb-legend">' + ["A", "B", "C", "D", "E", "F"].map(function (k) {
        return g[k] ? '<i class="seg" data-g="' + k + '" data-w="' + (g[k] / sum) + '"></i>' : "";
      }).join("") + "</span>" +
      '<ol class="fb-legend" id="fb-legend">' + ["A", "B", "C", "D", "E", "F"].map(function (k) {
        return "<li>" + chip(k) + '<span class="fb-legend-n">' + num(g[k] || 0) + "</span></li>";
      }).join("") + "</ol>" +
      '<p class="fb-key"><span><b>A, B</b> post-quantum key exchange</span><span><b>C to F</b> classical, or a certificate or protocol to fix</span></p>';
    dist.removeAttribute("aria-busy");
    widths(dist);
  }
  function widths(root) {
    Array.prototype.forEach.call(root.querySelectorAll("[data-w]"), function (el) {
      el.style.width = (Math.max(0, Math.min(1, Number(el.getAttribute("data-w")))) * 100).toFixed(2) + "%";
    });
  }

  /* ── the sector board ── */
  function spark(trend) {
    if (!trend || trend.length < 2) return "";
    var w = 64, h = 18, n = trend.length;
    var pts = trend.map(function (t, i) { return (i * (w - 2) / (n - 1) + 1).toFixed(1) + "," + (h - 1 - (t.pq_share || 0) * (h - 2)).toFixed(1); }).join(" ");
    return '<svg class="fb-spark" viewBox="0 0 ' + w + " " + h + '" preserveAspectRatio="none" aria-hidden="true" focusable="false"><polyline points="' + pts + '"/></svg>';
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
  function paintSectors(L) {
    S.league = L;
    var box = $("#fb-sec");
    var list = (L.sectors || []).filter(function (s) { return s.graded; }).slice().sort(function (a, b) { return String(a.name).localeCompare(String(b.name)); });
    box.removeAttribute("aria-busy");
    if (!list.length) { box.innerHTML = '<li class="fb-empty">No sector has graded sites on this server yet. The sector lists are re-graded weekly, a few sites at a time.</li>'; return; }
    box.innerHTML = list.map(function (s) {
      var tw = trendWords(s.trend);
      return '<li class="fb-s"><button type="button" class="fb-s-b" data-s="' + esc(s.id) + '" aria-pressed="' + (S.sector === s.id) + '">' +
        '<span class="fb-s-name">' + esc(s.name) + "</span>" +
        '<span class="fb-s-pct">' + pct1(s.pq_share) + "<small>%</small></span>" +
        '<span class="fb-s-bar" aria-hidden="true"><i data-w="' + (s.pq_share || 0) + '"></i></span>' +
        '<span class="fb-s-foot"><span class="fb-s-tr" data-dir="' + (tw.dir || "") + '" aria-hidden="true">' + spark(s.trend) + esc(tw.t) + "</span>" +
        '<span class="fb-s-n" aria-hidden="true">' + num(s.graded) + " sites</span></span>" +
        '<span class="sr-only">: ' + pct1(s.pq_share) + " percent of " + num(s.graded) + " graded sites use a quantum-safe key exchange, " + esc(tw.sr) + ". Show this sector&rsquo;s sites below.</span>" +
        '</button><a class="fb-s-r" href="/report/' + enc(s.id) + '">Report<span class="sr-only"> on ' + esc(s.name) + "</span> &rarr;</a></li>";
    }).join("");
    widths(box);
    box.addEventListener("click", function (e) {
      var b = e.target.closest("button[data-s]"); if (!b) return;
      pick(S.sector === b.getAttribute("data-s") ? "" : b.getAttribute("data-s"));
    });
    filterLine();
  }
  function sectorName(id) {
    var hit = ((S.league && S.league.sectors) || []).filter(function (s) { return s.id === id; })[0];
    return hit ? hit.name : id;
  }
  function pick(id) {
    S.sector = id;
    I().setParam("sector", id || null);
    Array.prototype.forEach.call(document.querySelectorAll("#fb-sec button[data-s]"), function (b) { b.setAttribute("aria-pressed", String(b.getAttribute("data-s") === id)); });
    filterLine();
    paintUps(); paintReady(); paintNot();
  }
  function filterLine() {
    var f = $("#fb-filter"); if (!f) return;
    f.innerHTML = S.sector ? 'Sector: <b>' + esc(sectorName(S.sector)) + '</b> <button type="button" class="fb-clear" id="fb-clear">All sectors</button>' : "All sectors";
    var c = $("#fb-clear"); if (c) c.addEventListener("click", function () { pick(""); var q = $("#fb-q"); if (q) q.focus(); });
  }

  /* ── the three named lists ── */
  function matches(e) {
    return (!S.sector || e.sector === S.sector) && (!S.q || String(e.domain).indexOf(S.q) >= 0);
  }
  function setCount(id, text) { var n = $("#" + id + "-n"); if (n) n.textContent = text; }
  function done(id) { var c = $("#" + id + "-col"); if (c) c.removeAttribute("aria-busy"); }
  function unavailable(id, what, e) {
    $("#" + id).innerHTML = '<li class="fb-empty">' + esc(what) + " could not be read just now" + (e && e.status ? " (HTTP " + e.status + ")" : "") + ". The domain box above still works.</li>";
    setCount(id, ""); done(id);
  }
  function item(href, g, prev, domain, words, extra) {
    return '<li class="fb-row"><a class="fb-item" href="' + href + '">' +
      '<span class="fb-g">' + (prev ? chip(prev) + '<span class="fb-to" aria-label="to">&rarr;</span>' : "") + chip(g) + "</span>" +
      '<span class="fb-d">' + esc(domain) + "</span>" +
      '<span class="fb-w">' + words + "</span></a>" + (extra || "") + "</li>";
  }
  function replyHtml(r) {
    return r ? '<p class="fb-reply"><span class="fb-k">Owner&rsquo;s reply, ' + esc(when(r.at)) + "</span> &ldquo;" + esc(r.text) + "&rdquo;</p>" : "";
  }

  function paintUps() {
    if (!S.ups) return;
    var all = (S.ups.events || []).filter(function (e) { return e.kind === "ready" && e.named && e.domain; });
    var rows = all.filter(matches);
    setCount("fb-up", rows.length ? num(rows.length) + (rows.length > SAMPLE ? " · newest " + SAMPLE : "") : "");
    $("#fb-up").innerHTML = rows.length ? rows.slice(0, SAMPLE).map(function (e) {
      var kx = e.group ? "post-quantum key exchange (" + esc(e.group) + ")" : "graded " + esc(e.grade);
      return item("/r/" + enc(e.domain), e.grade, e.previous_grade, e.domain, "Measured " + esc(when(e.at)) + ": " + kx, replyHtml(e.reply));
    }).join("") : '<li class="fb-empty">' + (S.q || S.sector
      ? "No site" + (S.sector ? " in " + esc(sectorName(S.sector)) : "") + (S.q ? " matching &ldquo;" + esc(S.q) + "&rdquo;" : "") + " has moved up to A or B recently."
      : "No well-known site has moved up to A or B yet. When a weekly re-check finds one that switched to a post-quantum key exchange, it appears here first.") + "</li>";
    $("#fb-up-f").innerHTML = '<a href="/changes">Everything that changed</a><a href="/api/public/changes.rss">RSS</a><a href="/api/public/changes.atom">Atom</a>';
    done("fb-up");
  }
  function paintReady() {
    if (!S.ready) return;
    var rows = (S.ready.entries || []).filter(matches);
    setCount("fb-ready", rows.length ? num(rows.length) + " listed" : "");
    $("#fb-ready").innerHTML = rows.length ? rows.slice(0, SAMPLE).map(function (e) {
      return item("/r/" + enc(e.domain), e.grade, null, e.domain, "Owner verified &middot; measured " + esc(when(e.checked_at)) + " &middot; listed since " + esc(when(e.joined_at)));
    }).join("") : (S.ready.entries || []).length
      ? '<li class="fb-empty">No verified site' + (S.sector ? " in " + esc(sectorName(S.sector)) : "") + (S.q ? " matches &ldquo;" + esc(S.q) + "&rdquo;" : "") + ".</li>"
      : '<li class="fb-cta"><p><b>No organisation has listed itself yet.</b> Own a domain that grades A or B? Check it in the box above, choose <i>Claim it</i> on its record, and list it here once it is verified.</p>' +
        '<a class="i-btn" href="#home-q" id="fb-claim">Check your domain</a></li>';
    $("#fb-ready-f").innerHTML = '<span>' + esc(S.ready.about ? "By name. Re-checked weekly; leaves below B." : "") + '</span><a href="/api/public/pq-ready.atom">Atom</a>';
    var c = $("#fb-claim");
    if (c) c.addEventListener("click", function (e) { var q = document.getElementById("home-q"); if (q) { e.preventDefault(); q.focus(); q.scrollIntoView({ block: "center" }); } });
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
    var seq = ++S.seq;
    var url = "/api/public/not-ready?order=checked&limit=" + SAMPLE + (S.sector ? "&sector=" + enc(S.sector) : "") + (S.q ? "&q=" + enc(S.q) : "");
    var col = $("#fb-not-col"); if (col) col.setAttribute("aria-busy", "true");
    load(url).then(function (N) {
      if (seq !== S.seq) return;
      var list = (N.entries || []).filter(matches);   // an older server answers the whole list; filter here too
      var total = N.count || 0, matched = N.matched != null ? N.matched : list.length;
      list.sort(function (a, b) { return String(b.checked_at || "").localeCompare(String(a.checked_at || "")) || String(a.domain).localeCompare(String(b.domain)); });
      setCount("fb-not", S.q ? num(matched) + " match" + (matched === 1 ? "" : "es") : num(total) + " sites");
      $("#fb-not").innerHTML = list.length ? list.slice(0, SAMPLE).map(function (e) {
        return item("/r/" + enc(e.domain), e.grade, null, e.domain, notWords(e), replyHtml(e.reply));
      }).join("") : '<li class="fb-empty">' + (S.q ? "No listed site matches &ldquo;" + esc(S.q) + "&rdquo;" + (S.sector ? " in " + esc(sectorName(S.sector)) : "") + "."
        : "No site from the popular-sites list is below B on this server" + (S.sector ? " in " + esc(sectorName(S.sector)) : "") + ".") + "</li>";
      var m = N.methodology || {}, w = m.decrypt_window || {};
      var all = "/league" + (S.sector ? "?nr=" + enc(S.sector) : "");
      $("#fb-not-f").innerHTML = '<a class="fb-all" href="' + all + '">See all ' + num(total) + (S.sector ? " in " + esc(sectorName(S.sector)) : "") + " &rarr;</a>" +
        '<span>Newest checks first. Years ' + esc(w.low || 2035) + "&ndash;" + esc(w.high || 2040) + ' from <a href="' + esc(w.source_url || "/report") + '" rel="noopener">' + esc(w.source || "the cited source") + "</a>.</span>";
      done("fb-not");
      searchLine(matched);
    }).catch(function (e) { if (seq === S.seq) { unavailable("fb-not", "The not-yet-post-quantum list", e); searchLine(null); } });
  }
  function searchLine(notMatched) {
    var st = $("#fb-status"); if (!st) return;
    if (!S.q) { st.innerHTML = ""; return; }
    var ups = S.ups ? (S.ups.events || []).filter(function (e) { return e.kind === "ready" && e.named && matches(e); }).length : 0;
    var ready = S.ready ? (S.ready.entries || []).filter(matches).length : 0;
    var n = ups + ready + (notMatched || 0);
    var d = I().asDomain(S.q);
    var live = d ? ' <a href="/r/' + enc(d) + '">Check ' + esc(d) + " live &rarr;</a>" : " Type the full domain, like example.com, to check it live.";
    st.innerHTML = n ? num(n) + " listed site" + (n === 1 ? "" : "s") + " match &ldquo;" + esc(S.q) + "&rdquo;." + (d ? live : "")
      : "&ldquo;" + esc(S.q) + "&rdquo; is not in these lists" + (S.sector ? " for " + esc(sectorName(S.sector)) : "") + "." + live;
  }

  function $(s) { return document.querySelector(s); }

  function mount(box) {
    if (!box) return;
    S.box = box;
    S.sector = (I().param && I().param("sector")) || "";
    if (!/^[a-z0-9-]{1,40}$/.test(S.sector)) S.sector = "";
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
    var go = function () {
      load("/api/public/stats").then(paintStats).catch(function (e) {
        $("#fb-big").innerHTML = ""; $("#fb-h").classList.add("fb-h-off");
        $("#fb-say").textContent = "This week’s counts could not be read just now" + (e && e.status ? " (HTTP " + e.status + ")" : "") + ". The domain box above still works.";
        $("#fb-dist").innerHTML = ""; $("#fb-dist").removeAttribute("aria-busy");
      });
      load("/api/public/league").then(paintSectors).catch(function (e) {
        var b = $("#fb-sec"); b.removeAttribute("aria-busy");
        b.innerHTML = '<li class="fb-empty">The sector averages could not be read just now' + (e && e.status ? " (HTTP " + e.status + ")" : "") + '. <a href="/league">Open the league</a>.</li>';
      });
      load("/api/public/changes?kind=ready&limit=100").then(function (C) { S.ups = C; paintUps(); }).catch(function (e) { unavailable("fb-up", "The change feed", e); });
      load("/api/public/pq-ready").then(function (Q) { S.ready = Q; paintReady(); }).catch(function (e) { unavailable("fb-ready", "The verified list", e); });
      paintNot();
    };
    if (window.requestAnimationFrame) requestAnimationFrame(function () { setTimeout(go, 0); }); else setTimeout(go, 0);
  }

  window.MorrowBoard = { mount: mount };
})();
