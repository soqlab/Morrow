/* Wall mode: the screen behind a display link (services/display_links.py).

   The link is /wall#t=<token>[&theme=light]. The fragment never leaves this browser: the token goes
   only to GET /api/public/wall, as the X-Display-Token header, and the page talks to nothing else.
   Every minute the page asks again with If-None-Match; on errors it waits longer (up to 15 minutes).
   When it cannot reach Morrow it keeps the last real values, dims them and says how old they are.
   It never shows a number the server did not send. */
(function () {
  "use strict";
  var POLL_MS = 60000, MAX_MS = 900000, STALE_MS = 5 * 60000, SHIFT_MS = 3 * 60000;
  var $ = function (id) { return document.getElementById(id); };
  var wall = $("wall");
  var token = "", etag = "", lastOk = 0, dataAsOf = null, failures = 0, timer = 0, stopped = false, loaded = false;

  function readHash() {
    var params = new URLSearchParams(String(location.hash || "").replace(/^#/, ""));
    token = params.get("t") || "";
    document.documentElement.setAttribute("data-theme", params.get("theme") === "light" ? "light" : "dark");
  }

  function ago(ms) {
    var s = Math.max(0, Math.round(ms / 1000));
    if (s < 60) return "just now";
    var m = Math.round(s / 60);
    if (m < 60) return m === 1 ? "1 minute ago" : m + " minutes ago";
    var h = Math.round(m / 60);
    if (h < 48) return h === 1 ? "1 hour ago" : h + " hours ago";
    var d = Math.round(h / 24);
    return d + " days ago";
  }

  function clock(t) {
    return new Date(t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }

  function paintFoot() {
    var now = Date.now();
    if (!lastOk) { $("wallUpdated").textContent = ""; $("wallAge").textContent = ""; return; }
    var stale = now - lastOk > STALE_MS;
    if (stale && wall.dataset.state === "live") wall.dataset.state = "stale";
    if (!stale && wall.dataset.state === "stale") wall.dataset.state = "live";
    $("wallUpdated").textContent = stale
      ? "Can't reach Morrow. Last updated " + ago(now - lastOk) + " (" + clock(lastOk) + ")."
      : "Updated " + clock(lastOk);
    var as = dataAsOf ? Date.parse(dataAsOf) : NaN;
    $("wallAge").textContent = isNaN(as) ? "No data behind this yet" : "Data from " + ago(now - as);
  }

  function render(body) {
    loaded = true;
    $("wallSentence").textContent = body.sentence || "";
    var n = body.number || {};
    var has = n.value !== null && n.value !== undefined;
    $("wallValue").textContent = has ? String(n.value) + (n.unit || "") : "–";
    $("wallValue").setAttribute("aria-label", has ? String(n.value) + (n.unit || "") : "no value");
    $("wallLabel").textContent = has ? (n.label || "") : "";
    $("wallDetail").textContent = n.detail || "";
    $("wallNumber").hidden = false;
    dataAsOf = body.data_as_of || null;
  }

  function deny(message) {
    stopped = true;
    wall.dataset.state = "denied";
    $("wallSentence").textContent = message;
    $("wallNumber").hidden = true;
    lastOk = 0;
    paintFoot();
  }

  function schedule() {
    clearTimeout(timer);
    if (stopped) return;
    var wait = failures ? Math.min(MAX_MS, POLL_MS * Math.pow(2, failures)) : POLL_MS;
    timer = setTimeout(tick, wait);
  }

  function tick() {
    if (!token) { deny("This screen has no display link. An admin can make one in Morrow: Administration, Display links."); return; }
    var headers = { "X-Display-Token": token, "Accept": "application/json" };
    if (etag) headers["If-None-Match"] = etag;
    fetch("/api/public/wall", { headers: headers, cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer" })
      .then(function (res) {
        if (res.status === 304) return null;
        if (res.status === 401) {
          return res.json().catch(function () { return {}; }).then(function (b) {
            deny((b && b.detail) || "This display link no longer works. Ask an admin for a new one.");
            throw { handled: true };
          });
        }
        if (!res.ok) throw new Error("HTTP " + res.status);
        etag = res.headers.get("ETag") || "";
        return res.json();
      })
      .then(function (body) {
        if (body) render(body);
        if (loaded) { lastOk = Date.now(); failures = 0; wall.dataset.state = "live"; }
        paintFoot();
        schedule();
      })
      .catch(function (e) {
        if (e && e.handled) return;
        failures += 1;
        if (!loaded) $("wallSentence").textContent = "Can't reach Morrow yet. Trying again.";
        paintFoot();
        schedule();
      });
  }

  /* Burn-in: move the whole layout a few pixels every few minutes, unless motion is reduced. */
  var still = window.matchMedia ? window.matchMedia("(prefers-reduced-motion: reduce)") : { matches: false };
  function shift() {
    if (still.matches) { wall.style.transform = ""; return; }
    var dx = Math.round((Math.random() * 2 - 1) * 14), dy = Math.round((Math.random() * 2 - 1) * 10);
    wall.style.transform = "translate(" + dx + "px," + dy + "px)";
  }

  readHash();
  window.addEventListener("hashchange", function () {
    readHash(); etag = ""; stopped = false; failures = 0; loaded = false; lastOk = 0;
    wall.dataset.state = "loading"; tick();
  });
  setInterval(paintFoot, 15000);
  setInterval(shift, SHIFT_MS);
  tick();
})();
