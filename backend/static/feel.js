/*
 * The feel of every public Morrow page (static/feel.css has the look). Loaded in <head> without
 * defer on purpose: the first lines set the visitor's chosen theme before anything is painted.
 * Same origin only; no inline script or style, so it runs under every page's CSP.
 *
 *   theme        follows the device (prefers-color-scheme) until the visitor presses the header's
 *                switch; the choice is kept in this browser (localStorage "morrow_theme", the
 *                key the console uses too) and applied as html[data-theme].
 *   count(root)  numbers marked data-count count up once, from zero, when they scroll into view.
 *   grow(root)   bars marked data-w (a share, 0 to 1) grow to their width once they are in view.
 *   copied(btn)  the "Copied" answer on a copy button; [data-copy-from] buttons copy an element.
 *   since(...)   "changed since your last visit", from what this browser saw last time. Nothing
 *                here leaves the browser: no request is made for it and nothing is sent.
 *
 * Nothing loops: a count-up is one run of frames that ends, a bar is one transition, and under
 * prefers-reduced-motion every value is simply shown.
 */
(function () {
  "use strict";
  var KEY = "morrow_theme";
  var root = document.documentElement;
  function get(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
  function put(k, v) { try { if (v == null) localStorage.removeItem(k); else localStorage.setItem(k, v); } catch (e) { /* private mode */ } }
  var chosen = get(KEY);
  if (chosen === "light" || chosen === "dark") root.setAttribute("data-theme", chosen);

  var REDUCED = !!(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches);
  function current() {
    var t = root.getAttribute("data-theme");
    if (t === "light" || t === "dark") return t;
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  }
  function paintToggle(btn) {
    var next = current() === "dark" ? "light" : "dark";
    btn.setAttribute("aria-label", "Switch to the " + next + " theme");
    var t = btn.querySelector(".i-theme-t");
    if (t) t.textContent = next === "dark" ? "Dark" : "Light";
  }
  function bindTheme() {
    Array.prototype.forEach.call(document.querySelectorAll("[data-theme-toggle]"), function (btn) {
      btn.hidden = false;
      paintToggle(btn);
      btn.addEventListener("click", function () {
        var next = current() === "dark" ? "light" : "dark";
        root.setAttribute("data-theme", next);
        put(KEY, next);
        Array.prototype.forEach.call(document.querySelectorAll("[data-theme-toggle]"), paintToggle);
      });
    });
  }

  /* ── numbers that count up once ── */
  var NUM = /^(\D*?)(\d{1,3}(?:,\d{3})+|\d+)(\.\d+)?(\D*)$/;
  var counted = {};
  function fmt(v, dec, grouped) {
    var s = v.toFixed(dec);
    if (!grouped) return s;
    var p = s.split(".");
    p[0] = p[0].replace(/\B(?=(\d{3})+(?!\d))/g, ",");
    return p.join(".");
  }
  function run(el) {
    var text = el.getAttribute("data-count-text");
    var m = NUM.exec(text || "");
    if (!m) { el.textContent = text; return; }
    var to = Number(m[2].replace(/,/g, "") + (m[3] || "")), dec = m[3] ? m[3].length - 1 : 0, grouped = m[2].indexOf(",") >= 0;
    var t0 = null, D = 700;
    function step(t) {
      if (!el.isConnected) return;
      if (t0 == null) t0 = t;
      var k = Math.min(1, (t - t0) / D), e = 1 - Math.pow(1 - k, 3);
      el.textContent = k < 1 ? m[1] + fmt(to * e, dec, grouped) + m[4] : text;
      if (k < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }
  function count(scope) {
    var els = Array.prototype.slice.call((scope || document).querySelectorAll("[data-count]:not([data-count-text])"));
    if (!els.length) return;
    var io = !REDUCED && window.IntersectionObserver && window.requestAnimationFrame ? new IntersectionObserver(function (entries) {
      entries.forEach(function (en) { if (en.isIntersecting) { io.unobserve(en.target); run(en.target); } });
    }, { threshold: 0.4 }) : null;
    els.forEach(function (el) {
      var text = el.textContent;
      el.setAttribute("data-count-text", text);
      var m = NUM.exec(text);
      // Once per value per page: a panel painted again with the same number does not count again.
      var key = location.pathname + "|" + (el.getAttribute("data-count") || "") + "|" + text;
      // Only a number that is laid out can scroll into view; one in a closed <details> keeps its value.
      if (!io || !m || counted[key] || !el.getClientRects().length) return;
      counted[key] = true;
      el.textContent = m[1] + fmt(0, m[3] ? m[3].length - 1 : 0, m[2].indexOf(",") >= 0) + m[4];
      io.observe(el);
    });
  }

  /* ── bars that grow once ── */
  function grow(scope) {
    var els = Array.prototype.slice.call((scope || document).querySelectorAll("[data-w]:not([data-grown])"));
    if (!els.length) return;
    var set = function (el) {
      el.setAttribute("data-grown", "1");
      var w = Math.max(0, Math.min(1, Number(el.getAttribute("data-w")) || 0));
      el.style.width = (w * 100).toFixed(2) + "%";
    };
    if (REDUCED || !window.IntersectionObserver) { els.forEach(set); return; }
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) { if (en.isIntersecting) { io.unobserve(en.target); set(en.target); } });
    }, { threshold: 0.2 });
    els.forEach(function (el) { el.style.width = "0%"; io.observe(el); });
  }

  /* ── copy, and the answer ── */
  function copied(btn, label) {
    if (!btn) return;
    if (!btn.hasAttribute("data-label")) btn.setAttribute("data-label", btn.textContent);
    clearTimeout(btn._feelT);
    btn.textContent = label || "Copied";
    btn.classList.remove("is-copied"); void btn.offsetWidth; btn.classList.add("is-copied");
    btn._feelT = setTimeout(function () { btn.textContent = btn.getAttribute("data-label"); btn.classList.remove("is-copied"); }, 1600);
  }
  function copyText(text, btn) {
    var fail = function () { copied(btn, "Select and copy"); };
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(function () { copied(btn); }, fail);
    else fail();
  }
  function bindCopy() {
    Array.prototype.forEach.call(document.querySelectorAll("[data-copy-from], [data-copy-text]"), function (btn) {
      if (btn._feelCopy) return;
      btn._feelCopy = true;
      btn.hidden = false;
      btn.addEventListener("click", function () {
        var src = btn.getAttribute("data-copy-from");
        var text = src ? (document.getElementById(src) || {}).textContent : btn.getAttribute("data-copy-text");
        if (text) copyText(String(text).trim(), btn);
      });
    });
  }

  /* ── since your last visit ── */
  function day(iso) {
    var d = new Date(iso);
    return isNaN(d) ? "" : d.toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" });
  }
  function readMap(k) { try { var v = JSON.parse(get(k) || "{}"); return v && typeof v === "object" ? v : {}; } catch (e) { return {}; } }
  function writeMap(k, map, cap) {
    var keys = Object.keys(map);
    if (keys.length > cap) keys.sort(function (a, b) { return String(map[a].at).localeCompare(String(map[b].at)); }).slice(0, keys.length - cap).forEach(function (x) { delete map[x]; });
    put(k, JSON.stringify(map));
  }
  /* A record page carries data-seen-key (the domain), data-seen-value (what was measured, e.g. the
     observation id) and data-seen-label (that measurement in words). The line under the head says
     whether it moved since this browser last opened the page. The first visit says nothing. */
  function recordSince() {
    var el = document.querySelector("[data-seen-key]"), out = document.getElementById("feel-since");
    if (!el || !out) return;
    var key = el.getAttribute("data-seen-key"), value = el.getAttribute("data-seen-value") || "", label = el.getAttribute("data-seen-label") || "";
    var map = readMap("morrow_record_seen"), prev = map[key], now = new Date().toISOString();
    map[key] = { v: value, l: label, at: now };
    writeMap("morrow_record_seen", map, 60);
    if (!prev || !prev.at) return;
    var when = day(prev.at), parts;
    if (prev.v === value) parts = ["Unchanged since your last visit on " + when + "."];
    else if (prev.l && prev.l !== label) parts = ["Changed since your last visit on " + when + ": " + prev.l + " → ", label, "."];
    else parts = ["Measured again since your last visit on " + when + "; still ", label, "."];
    out.textContent = "";
    var k = document.createElement("span"); k.className = "feel-since-k"; k.textContent = "Since your last visit"; out.appendChild(k);
    var line = document.createElement("span");
    parts.forEach(function (p, i) { var n = document.createElement(i === 1 ? "b" : "span"); n.textContent = p; line.appendChild(n); });
    out.appendChild(line);
    out.setAttribute("data-tone", prev.v === value ? "same" : "new");
    out.hidden = false;
  }
  /* For a list view (what changed, the league): how many of these are new since this browser last
     looked. items: [{at: iso}], key: one per list and filter. Returns {n, since} or null the first
     time, and remembers the newest item for next time. */
  function since(key, newest, isNew) {
    var map = readMap("morrow_list_seen"), prev = map[key], now = new Date().toISOString();
    map[key] = { newest: newest || (prev && prev.newest) || "", at: now };
    writeMap("morrow_list_seen", map, 40);
    if (!prev || !prev.at) return null;
    return { since: day(prev.at), mark: prev.newest || "", isNew: isNew };
  }
  function sinceLine(text, tone) {
    return '<p class="feel-since" data-tone="' + (tone || "new") + '" role="status"><span class="feel-since-k">Since your last visit</span><span>' + text + "</span></p>";
  }

  /* ── build line on the server-rendered pages (the instrument fills its own) ── */
  function buildLine() {
    var f = document.querySelector("#i-build[data-build]");
    if (!f || !window.fetch) return;
    fetch("/api/public/build", { cache: "no-store", credentials: "omit", headers: { Accept: "application/json" } })
      .then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
      .then(function (b) {
        if (!b || !b.commit) return;
        var esc = function (s) { return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/"/g, "&quot;"); };
        f.innerHTML = 'This server runs commit <a href="/trust"><b>' + esc(b.commit_short || String(b.commit).slice(0, 12)) + '</b></a> of <a href="' + esc(b.commit_url) + '" rel="noopener">soqlab/Morrow</a> &middot; <a href="/trust">check it</a>';
      }).catch(function () { /* the link to /trust stays */ });
  }

  /* The instrument paints its views after load: apply the same feel to whatever it adds. */
  function watchMain() {
    var main = document.getElementById("main");
    if (!main || !window.MutationObserver) return;
    var queued = false;
    new MutationObserver(function () {
      if (queued) return;
      queued = true;
      Promise.resolve().then(function () { queued = false; count(main); grow(main); bindCopy(); });
    }).observe(main, { childList: true, subtree: true });
  }

  function start() {
    bindTheme();
    count(document);
    grow(document);
    bindCopy();
    recordSince();
    buildLine();
    watchMain();
  }
  window.MorrowFeel = { count: count, grow: grow, copied: copied, copy: copyText, since: since, sinceLine: sinceLine, day: day, reduced: REDUCED };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start);
  else start();
})();
