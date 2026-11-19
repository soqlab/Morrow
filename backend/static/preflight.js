/*
 * Before you switch: pre-flight (services/preflight.py, GET /api/public/preflight/<domain>).
 *
 *   MorrowPreflight.html(domain)          the panel's frame, before anything is sent
 *   MorrowPreflight.mount(box, domain)    wire it: shows the newest stored run (no probe), and
 *                                         "Run pre-flight" asks the server for one
 *   <div data-preflight="example.com">    mounted on its own when the page loads (the /r pages)
 *
 * The race is a replay of the server's measured times, nothing else: every lane runs on one time
 * axis at the same speed, so a lane that took 12 ms finishes almost at once and a hello that got no
 * answer for 6 s runs the whole track and ends in a cross. Nothing moves until the person presses the
 * button, the replay runs once, and under prefers-reduced-motion the bars are drawn at their final
 * length straight away. Same origin only; no inline script or style; no storage.
 */
(function () {
  "use strict";

  var LANES = [
    { id: "classical", name: "Classical hello", hint: "about 250 bytes, one TCP segment" },
    { id: "pq", name: "Post-quantum hello", hint: "about 1,750 bytes, two TCP segments" },
    { id: "pq_split", name: "Post-quantum, in two parts", hint: "the same hello, sent in two pieces" }
  ];
  var ERRORS = { timeout: "No answer", reset: "Cut off", alert: "Refused", connect: "No connection", protocol: "Not TLS" };
  var REPLAY_MS = 1600;

  function esc(v) {
    return String(v == null ? "" : v).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function enc(v) { return encodeURIComponent(String(v || "")); }
  function num(n) { return Number(n || 0).toLocaleString("en-US"); }
  function reduced() {
    try { return window.matchMedia("(prefers-reduced-motion: reduce)").matches; } catch (e) { return false; }
  }
  function ms(v) { return v == null ? "" : v >= 1000 ? (v / 1000).toFixed(1) + " s" : v + " ms"; }
  function clock(iso) { var d = new Date(iso); return isNaN(d) ? "" : d.toISOString().slice(11, 16) + " UTC"; }
  function ago(iso) {
    var s = (Date.now() - Date.parse(iso)) / 1000;
    if (!(s >= 0)) return "";
    if (s < 90) return "just now";
    if (s < 5400) return Math.round(s / 60) + " minutes ago";
    if (s < 129600) return Math.round(s / 3600) + " hours ago";
    return Math.round(s / 86400) + " days ago";
  }

  function getJSON(url) {
    return fetch(url, { credentials: "omit", cache: "no-store", headers: { Accept: "application/json" } }).then(function (r) {
      return r.text().then(function (t) {
        var b = null; try { b = t ? JSON.parse(t) : null; } catch (e) { b = null; }
        if (!r.ok) {
          var err = new Error((b && b.detail) || ("The server answered " + r.status + "."));
          err.status = r.status; err.code = b && b.error; err.retryAfter = +(r.headers.get("Retry-After") || 0);
          throw err;
        }
        return b;
      });
    });
  }

  function lane(l) {
    return '<li class="pf-lane" data-id="' + l.id + '">' +
      '<div class="pf-name"><b>' + esc(l.name) + '</b><span class="pf-size">' + esc(l.hint) + "</span></div>" +
      '<div class="pf-track" aria-hidden="true"><span class="pf-bar"></span><span class="pf-mark"></span></div>' +
      '<div class="pf-out"><span class="pf-res">Not sent</span></div></li>';
  }

  function html(domain) {
    var d = esc(domain);
    return '<div class="pf" data-state="idle">' +
      '<p class="pf-lede">Browsers that offer post-quantum key exchange send a much larger first message (the ClientHello), ' +
      "often too large for one network packet, and some firewalls and load balancers drop it. Check the path to <b>" + d + "</b> before you switch: " +
      "Morrow sends a classical hello and a post-quantum one, side by side.</p>" +
      '<ol class="pf-race" aria-label="The hellos Morrow sends">' + LANES.map(lane).join("") + "</ol>" +
      '<p class="pf-axis pf-fine" aria-hidden="true"></p>' +
      '<div class="pf-act"><button type="button" class="i-btn solid pf-go">Run pre-flight</button>' +
      '<span class="pf-fine pf-say" role="status" aria-live="polite">Up to six connections to port 443 from Morrow\'s server, closed after the first answer.</span></div>' +
      '<div class="pf-verdict" tabindex="-1" hidden></div>' +
      '<p class="pf-scope">This is an outside test: it covers the public path from the internet to ' + d + ", not your internal networks. " +
      '<a class="pf-inside" href="https://github.com/soqlab/Morrow/blob/main/tools/preflight/README.md" rel="noopener">Test from inside your network</a></p>' +
      "</div>";
  }

  function laneEl(box, id) { return box.querySelector('.pf-lane[data-id="' + id + '"]'); }

  function laneText(h) {
    var size = num(h.hello_bytes) + " bytes, " + (h.segments_sent || 1) + (h.segments_sent === 1 ? " segment" : " segments");
    if (h.completed) return { mark: "ok", res: ms(h.ms) + (h.group ? " · " + h.group : ""), size: size,
      say: "answered in " + ms(h.ms) + (h.group ? ", chose " + h.group : "") };
    var label = ERRORS[h.error] || "Failed";
    var when = h.failed_after_ms != null ? " after " + ms(h.failed_after_ms) : "";
    return { mark: "bad", res: label + when, size: size, say: (h.error_detail || label) + when };
  }

  function duration(h) {
    if (h.completed) return Math.max(1, h.ms || 1);
    if (h.failed_after_ms != null) return Math.max(1, h.failed_after_ms);
    return h.ms != null ? Math.max(1, h.ms) : 1;
  }

  function paintLanes(box, result, animate) {
    var hs = result.handshakes || [];
    var top = 1;
    hs.forEach(function (h) { top = Math.max(top, duration(h)); });
    var axis = box.querySelector(".pf-axis");
    axis.textContent = "One time axis for every lane: the full track is " + ms(top) + ", the slowest" +
      (animate ? ". Replayed at the measured speed." : ".");
    axis.classList.add("on");
    LANES.forEach(function (l) {
      var el = laneEl(box, l.id);
      if (!el) return;
      var h = null;
      hs.forEach(function (x) { if (x.id === l.id) h = x; });
      el.hidden = !h;
      if (!h) return;
      var t = laneText(h);
      var bar = el.querySelector(".pf-bar");
      var frac = Math.max(0.012, duration(h) / top);
      el.querySelector(".pf-size").textContent = t.size;
      el.setAttribute("aria-label", l.name + ", " + t.size + ": " + t.say + (h.attempts > 1 ? " (tried twice)" : ""));
      el.removeAttribute("data-result");
      var finish = function () {
        el.setAttribute("data-result", t.mark);
        el.querySelector(".pf-res").textContent = t.res + (h.attempts > 1 ? " · tried twice" : "");
      };
      bar.style.transitionDuration = "0ms";
      bar.style.transform = "scaleX(" + (animate ? 0 : frac) + ")";
      if (!animate) { finish(); return; }
      el.querySelector(".pf-res").textContent = "…";
      // One axis, one speed: the lane's duration is its share of the slowest lane's replay.
      var dur = Math.round(REPLAY_MS * frac);
      void bar.offsetWidth;
      bar.style.transitionDuration = dur + "ms";
      bar.style.transform = "scaleX(" + frac + ")";
      setTimeout(finish, dur + 40);
    });
    return animate ? REPLAY_MS + 120 : 0;
  }

  function paintVerdict(box, result) {
    var v = result.verdict || {};
    var out = box.querySelector(".pf-verdict");
    var fixes = (v.fixes || []).map(function (f) {
      return "<li><b>" + esc(f.title) + ".</b> " + esc(f.detail) + (f.source ? ' <a href="' + esc(f.source) + '" rel="noopener">Source</a>' : "") + "</li>";
    }).join("");
    var notes = (v.notes || []).map(function (n) { return '<p class="pf-fine">' + esc(n) + "</p>"; }).join("");
    var m = result.measured || {};
    var sources = (result.sources || []).map(function (s) { return '<li><a href="' + esc(s.url) + '" rel="noopener">' + esc(s.name) + "</a>: " + esc(s.says) + "</li>"; }).join("");
    var not = (result.not_tested || []).map(function (n) { return "<li>" + esc(n) + "</li>"; }).join("");
    var outside = (m.does_not_cover || []).map(function (n) { return "<li>" + esc(n) + "</li>"; }).join("");
    out.setAttribute("data-v", v.id || "");
    out.innerHTML = '<p class="pf-v-h"><span class="pf-v-ic" aria-hidden="true"></span>' + esc(v.headline) + "</p>" +
      "<p>" + esc(v.detail) + "</p>" +
      (v.cause ? '<p class="pf-cause"><b>Likely cause.</b> ' + esc(v.cause) + "</p>" : "") +
      (fixes ? '<p class="pf-sub">What fixes it</p><ol class="pf-fixes">' + fixes + "</ol>" : "") + notes +
      '<p class="pf-fine pf-when">' + esc(m.wording || "") + (result.cached && Date.parse(result.next_check_after) > Date.now() ? " Reused: one run per domain every few minutes, whoever asks; the next one can start after " + esc(clock(result.next_check_after)) + "." : "") + "</p>" +
      '<details class="pf-more"><summary>What this covers, and the sources</summary>' +
      "<p>" + esc(m.covers || "") + "</p>" + (outside ? "<p>It does not cover:</p><ul>" + outside + "</ul>" : "") +
      (not ? "<p>Not tested here:</p><ul>" + not + "</ul>" : "") + (sources ? "<p>Sources:</p><ul>" + sources + "</ul>" : "") + "</details>";
    out.hidden = false;
  }

  function mount(box, domain) {
    if (!box || box.getAttribute("data-pf-mounted")) return;
    box.setAttribute("data-pf-mounted", "1");
    if (!box.querySelector(".pf")) box.innerHTML = html(domain);
    var root = box.querySelector(".pf");
    var go = root.querySelector(".pf-go");
    go.hidden = false;                       // a server-rendered frame hides it until this script runs
    var say = root.querySelector(".pf-say");
    var busy = false;

    function show(result, animate) {
      root.setAttribute("data-state", animate ? "racing" : "done");
      if (animate) root.setAttribute("data-anim", ""); else root.removeAttribute("data-anim");
      root.querySelector(".pf-verdict").hidden = true;
      var wait = paintLanes(root, result, animate);
      var land = function () {
        root.setAttribute("data-state", "done");
        paintVerdict(root, result);
        var v = result.verdict || {};
        say.textContent = (result.cached ? "Last run " + ago(result.checked_at) + ". " : "") + (v.headline || "");
        go.textContent = "Run again";
        go.disabled = false; go.removeAttribute("aria-busy"); busy = false;
      };
      if (wait) setTimeout(land, wait); else land();
    }

    go.addEventListener("click", function () {
      if (busy) return;
      busy = true;
      go.disabled = true; go.setAttribute("aria-busy", "true");
      root.setAttribute("data-state", "sending");
      root.querySelector(".pf-verdict").hidden = true;
      LANES.forEach(function (l) {
        var el = laneEl(root, l.id);
        if (!el) return;
        el.removeAttribute("data-result");
        el.querySelector(".pf-bar").style.transitionDuration = "0ms";
        el.querySelector(".pf-bar").style.transform = "scaleX(0)";
        el.querySelector(".pf-res").textContent = "Sending";
      });
      say.textContent = "Sending the hellos to " + domain + ". A hello that gets no answer takes a few seconds to give up on.";
      getJSON("/api/public/preflight/" + enc(domain)).then(function (result) {
        say.textContent = result.cached ? "Reusing the run from " + ago(result.checked_at) + "." : "Measured. Replaying the times.";
        show(result, !reduced() && !result.cached);
      }).catch(function (err) {
        root.setAttribute("data-state", "error");
        LANES.forEach(function (l) { var el = laneEl(root, l.id); if (el) el.querySelector(".pf-res").textContent = "Not sent"; });
        say.textContent = err.message + (err.retryAfter ? " Try again in about " + Math.max(1, Math.round(err.retryAfter / 60)) + " minutes." : "");
        go.disabled = false; go.removeAttribute("aria-busy"); busy = false;
      });
    });

    // The newest stored run, if any: read only, nothing is sent to the host.
    getJSON("/api/public/preflight/" + enc(domain) + "?stored=1").then(function (result) {
      if (busy || !result || !result.verdict) return;
      show(result, false);
    }).catch(function () { /* none stored yet: the panel stays idle */ });
  }

  function auto() {
    var boxes = document.querySelectorAll("[data-preflight]");
    for (var i = 0; i < boxes.length; i++) mount(boxes[i], boxes[i].getAttribute("data-preflight"));
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", auto); else auto();

  window.MorrowPreflight = { html: html, mount: mount };
})();
