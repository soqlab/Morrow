/*
 * Make it safe: the fix for the host's own stack, the watch, and the proof (instrument.js calls in here).
 *
 *   MorrowSafe.html()                      the panel's empty frame
 *   MorrowSafe.mount(box, d, r, opts)      fill it for domain d with grade result r
 *                                          opts.onLive(): called once the host turns post-quantum
 *
 * The fix comes from /api/public/make-safe/<d> (services/make_safe.py): the stack that terminates TLS,
 * the evidence for it, and the vendor-sourced change. "I've made the change" asks for spaced
 * re-checks (/api/public/make-safe/<d>/recheck); the server sets the spacing and this page only ever
 * waits for it. Re-checks pause while the tab is hidden and stop after the server's limit.
 * Same origin only; no inline script or style.
 */
(function () {
  "use strict";
  function I() { return window.MorrowIns; }
  var S = null;

  function send(url, body) {
    return fetch(url, { method: "POST", credentials: "omit", cache: "no-store",
      headers: { Accept: "application/json", "Content-Type": "application/json" }, body: JSON.stringify(body || {}) })
      .then(function (r) {
        return r.text().then(function (t) {
          var b = null; try { b = t ? JSON.parse(t) : null; } catch (e) { b = null; }
          if (!r.ok) { var err = new Error((b && b.detail) || ("HTTP " + r.status)); err.status = r.status; err.body = b; err.retryAfter = +(r.headers.get("Retry-After") || 0); throw err; }
          return b;
        });
      });
  }
  function esc(v) { return I().esc(v); }
  function time(iso) { var d = new Date(iso); return isNaN(d) ? "" : d.toISOString().slice(11, 16) + " UTC"; }
  var SUPPORT = { default_on: "On by default", opt_in: "One setting", not_documented: "No vendor setting yet", unknown: "Not identified" };

  function html() { return '<div id="ms-box"><p class="i-status" role="status">Reading what serves this host…</p></div>'; }

  function mount(box, d, r, opts) {
    if (!box) return;
    if (S && S.d === d && S.r && r && S.r.scanned_at === r.scanned_at) { S.box = box; if (S.plan || S.err) paint(); else if ((r.key_exchange || {}).post_quantum) paintSafe(); return; }
    if (S && S.timer) clearTimeout(S.timer);
    S = { box: box, d: d, r: r, opts: opts || {}, plan: null, err: null, watch: null, timer: null, copied: false, busy: false, msg: "", tone: null };
    var kx = (r && r.key_exchange) || {};
    if (kx.post_quantum) { paintSafe(); return; }
    loadPlan("");
  }

  function loadPlan(stack) {
    var d = S.d;
    I().getJSON("/api/public/make-safe/" + I().enc(d) + (stack ? "?stack=" + I().enc(stack) : ""), { cache: "no-store" })
      .then(function (p) { if (S.d !== d) return; S.plan = p; S.err = null; paint(); })
      .catch(function (e) { if (S.d !== d) return; S.err = e.message; paint(); });
    I().getJSON("/api/public/make-safe/" + I().enc(d) + "/watch", { cache: "no-store" })
      .then(function (w) { if (S.d === d && w && w.watch && w.watch.status !== "live" && w.watch.auto && w.watch.started_at && Date.now() - Date.parse(w.watch.started_at) < 7200000) { S.watch = w.watch; paint(); schedule(w.watch.next_check_in); } })
      .catch(function () {});
  }

  function paintSafe() {
    var d = S.d, kx = (S.r && S.r.key_exchange) || {};
    S.box.innerHTML = '<div class="ms-light" data-state="live" id="ms-light"><span class="ms-dot" aria-hidden="true"></span><p><b>Quantum-safe.</b> ' + esc(d) + " negotiates " + esc(kx.group || "post-quantum key exchange") + ". Nothing to change.</p></div>" +
      '<div class="ms-row"><a class="i-btn solid" href="/r/' + I().enc(d) + '/proof">The signed proof</a><span class="i-fine">Shareable, and anyone can check its signatures. If the host turns classical again, the proof says so.</span></div>';
  }

  function light() {
    var w = S.watch, kx = (S.r && S.r.key_exchange) || {};
    var state = w ? w.status : "red", text;
    if (!w) text = "<b>Not quantum-safe.</b> " + esc(S.d) + " negotiates " + esc(kx.group || "a classical key exchange") + ": traffic recorded today could be read once a quantum computer can break it.";
    else if (w.status === "live") text = "<b>Live.</b> " + esc(S.d) + " now negotiates " + esc(w.key_exchange || "post-quantum key exchange") + " (checked " + esc(time(w.last_checked_at)) + ").";
    else if (w.status === "error") text = "<b>That check did not complete.</b> " + esc(w.last_error || "") + (w.auto ? " Trying again in " + secs(w.next_check_in) + "." : "");
    else if (!w.attempts) text = "<b>Waiting to check.</b> First check in " + secs(w.next_check_in) + ".";
    else text = "<b>Not live yet.</b> Still " + esc(w.key_exchange || "classical") + " at " + esc(time(w.last_checked_at)) + "." +
      (w.auto ? " Checking again in " + secs(w.next_check_in) + "." : " Morrow stopped checking by itself after " + w.attempts + " tries; check again when you are ready.") + (w.attempts > 1 ? " A reload or a CDN cache purge is sometimes needed." : "");
    return '<div class="ms-light" data-state="' + esc(state) + '" id="ms-light" role="status" aria-live="polite"><span class="ms-dot" aria-hidden="true"></span><p>' + text + "</p></div>";
  }
  function secs(n) { n = Math.max(0, Math.round(+n || 0)); return n < 90 ? n + " s" : Math.round(n / 60) + " min"; }

  function recipeHtml(rc) {
    var depth = I().depth();
    var src = (rc.sources || []).map(function (s) {
      return '<li><a href="' + esc(s.url) + '" rel="noopener" target="_blank">' + esc(s.title) + "</a>" + (s.published ? ", published " + esc(s.published) : "") + ", checked " + esc(s.checked) + (depth === "expert" && s.quote ? ': "' + esc(s.quote) + '"' : "") + "</li>";
    }).join("");
    var needs = (rc.requires || []).length ? '<p class="ms-meta">Needs: ' + (rc.requires || []).map(esc).join("; ") + ".</p>" : "";
    var still = (rc.stays_classical_if || []).length ? '<details class="ms-more"><summary>Still classical after the change?</summary><ul class="ms-steps">' + rc.stays_classical_if.map(function (x) { return "<li>" + esc(x) + "</li>"; }).join("") + "</ul></details>" : "";
    return '<p>' + esc(rc.summary) + ' <span class="ms-conf" data-c="' + esc(rc.confidence) + '" title="How sure the vendor documentation makes this recipe">' + esc(SUPPORT[rc.support] || rc.support) + "</span></p>" +
      '<p class="ms-meta">' + esc(rc.snippet_label) + ":</p>" +
      '<div class="ms-pre"><pre id="ms-snippet" tabindex="0">' + esc(rc.snippet) + "</pre></div>" +
      '<div class="ms-row"><button type="button" class="i-btn" id="ms-copy">Copy</button></div>' + needs +
      (rc.notes && depth !== "plain" ? '<p class="ms-meta">' + esc(rc.notes) + "</p>" : "") +
      (rc.origin_note && depth !== "plain" ? '<p class="ms-meta">' + esc(rc.origin_note) + "</p>" : "") + still +
      (src ? '<p class="ms-meta">Source' + (rc.sources.length > 1 ? "s" : "") + " (the vendor's own documentation; confidence " + esc(rc.confidence) + '):</p><ul class="ms-src">' + src + "</ul>" : "");
  }

  function paint() {
    var box = S.box; if (!box || !document.body.contains(box)) { if (S.timer) clearTimeout(S.timer); return; }
    if (S.err && !S.plan) { box.innerHTML = light() + '<p class="i-status" data-tone="bad">' + esc(S.err) + "</p>"; return; }
    if (!S.plan) return;
    var p = S.plan, det = p.detected || {}, rc = p.recipe || {}, depth = I().depth();
    var who = det.stack === "unknown"
      ? "Morrow could not tell what terminates TLS for " + esc(p.domain) + ", so it will not guess a setting."
      : esc(p.domain) + " is served by <b>" + esc(det.name) + '</b> <span class="ms-conf" data-c="' + esc(det.confidence) + '">' + esc(det.confidence) + " confidence</span>";
    var ev = depth !== "plain" && (det.evidence || []).length ? '<ul class="ms-ev">' + det.evidence.map(function (e) { return "<li>" + esc(e) + "</li>"; }).join("") + "</ul>" : "";
    var alt = (det.alternatives || []).length && depth !== "plain" ? '<p class="ms-meta">Also seen: ' + det.alternatives.map(function (a) { return esc(a.name); }).join(", ") + ".</p>" : "";
    var pick = '<div class="ms-row"><label for="ms-stack">' + (det.stack === "unknown" ? "Pick your stack" : "Not right? Pick your stack") + '</label><select id="ms-stack" class="i-btn"><option value="">' + (det.stack === "unknown" ? "Not identified" : "Detected: " + esc(det.name)) + "</option>" +
      (p.stacks || []).map(function (s) { return '<option value="' + esc(s.id) + '"' + (p.chosen === s.id ? " selected" : "") + ">" + esc(s.name) + "</option>"; }).join("") + "</select></div>";
    var origin = p.origin_recipe && depth !== "plain" ? '<details class="ms-more"><summary>Behind ' + esc(det.name) + ": your origin runs " + esc(p.origin_recipe.name) + "</summary>" + recipeHtml(p.origin_recipe) + "</details>" : "";
    var w = S.watch, watching = w && w.status !== "live";
    var act = w && w.status === "live"
      ? '<div class="ms-row"><a class="i-btn solid" href="/r/' + I().enc(p.domain) + '/proof">Your signed proof</a><span class="i-fine">Quantum-safe since today. Share it; anyone can check its signatures.</span></div>'
      : '<div class="ms-row"><button type="button" class="i-btn' + (S.copied || !watching ? " solid" : "") + '" id="ms-done"' + (S.busy ? ' aria-busy="true"' : "") + ">" + (watching ? "Check again now" : "I've made the change") + "</button>" +
        '<span class="i-fine">' + (watching ? "Morrow checks by itself while this page is open, spaced out so your server is never hammered." : "Morrow then re-checks " + esc(p.domain) + " until the change is live.") + "</span></div>";
    var others = (S.r && S.r.fixes || []).filter(function (f) { return f.id !== "certificate-renew"; });
    var more = others.length && depth !== "plain" ? '<details class="ms-more"><summary>The full hardening change (old TLS versions and ciphers too)</summary>' + others.map(function (f) { return '<div class="fix"><p><b>' + esc(f.title) + "</b></p><pre>" + esc(f.snippet) + '</pre><p class="i-fine">Needs: ' + esc(f.requires) + "</p></div>"; }).join("") + "</details>" : "";
    var cert = (p.other_fixes || []).map(function (f) { return '<p class="ms-meta">Also: ' + esc(f.title) + ". " + esc(f.notes || "") + "</p>"; }).join("");
    box.innerHTML = light() + '<p class="ms-stack">' + who + "</p>" + ev + alt + recipeHtml(rc) + origin + act + pick + cert + more +
      (S.msg ? '<p class="i-status" data-tone="' + esc(S.tone || "") + '">' + esc(S.msg) + "</p>" : "");
    var c = box.querySelector("#ms-copy");
    if (c) c.addEventListener("click", function () { I().copy(rc.snippet, c); S.copied = true; var b = box.querySelector("#ms-done"); if (b) b.classList.add("solid"); });
    var done = box.querySelector("#ms-done");
    if (done) done.addEventListener("click", function () { recheck(true); });
    var sel = box.querySelector("#ms-stack");
    if (sel) sel.addEventListener("change", function () { S.plan = null; box.innerHTML = light() + '<p class="i-status">Reading the recipe…</p>'; loadPlan(sel.value); });
  }

  function schedule(seconds) {
    if (S.timer) clearTimeout(S.timer);
    var w = S.watch; if (!w || !w.auto || w.status === "live") return;
    var d = S.d;
    S.timer = setTimeout(function () {
      if (S.d !== d || !document.body.contains(S.box)) return;
      if (document.visibilityState !== "visible") {
        document.addEventListener("visibilitychange", function again() { if (document.visibilityState === "visible") { document.removeEventListener("visibilitychange", again); if (S.d === d) recheck(false); } });
        return;
      }
      recheck(false);
    }, Math.max(1, +seconds || 1) * 1000 + 250);
    tick();
  }
  function tick() {
    if (S.tickTimer) clearInterval(S.tickTimer);
    S.tickTimer = setInterval(function () {
      var w = S.watch; if (!w || w.status === "live" || !document.body.contains(S.box)) { clearInterval(S.tickTimer); return; }
      if (w.next_check_in > 0) { w.next_check_in -= 1; var el = S.box.querySelector("#ms-light"); if (el) el.outerHTML = light(); }
    }, 1000);
  }

  function recheck(start) {
    if (S.busy) return;
    var d = S.d;
    S.busy = true; S.msg = ""; paint();
    send("/api/public/make-safe/" + I().enc(d) + "/recheck", { start: !!start })
      .then(function (out) {
        if (S.d !== d) return;
        S.busy = false; S.watch = out.watch;
        paint();
        if (out.watch.status === "live") {
          I().flash(S.box.querySelector("#ms-light"));
          I().say(d + " is quantum-safe: " + (out.watch.key_exchange || "post-quantum key exchange") + " is live.");
          if (S.opts.onLive) S.opts.onLive(out);
        } else schedule(out.watch.next_check_in);
      })
      .catch(function (e) {
        if (S.d !== d) return;
        S.busy = false;
        if (e.status === 429 && e.body && e.body.watch) { S.watch = e.body.watch; paint(); schedule(e.retryAfter || e.body.watch.next_check_in); return; }
        S.msg = e.message + (e.retryAfter ? " Try again in " + secs(e.retryAfter) + "." : ""); S.tone = "bad";
        paint();
      });
  }

  window.MorrowSafe = { html: html, mount: mount };
})();
