/*
 * Make it safe: Done. One confirmed change at the DNS provider, then the live re-check, then the
 * signed proof. Self-contained: no other Morrow script is needed, same origin only, no inline
 * script or style (it runs under the strict CSP of /r and of the instrument views).
 *
 *   MorrowDone.mount(box, {domain, plan?, onLive?})  the Done offer for a host whose plan carries
 *                                                    plan.one_click (services/make_safe_done.py);
 *                                                    fetches the plan itself when none is given.
 *                                                    Renders nothing when there is no one-click fix.
 *   MorrowDone.watch(box, {domain, grade, kx, onLive?})
 *                                                    the same sequence after a change made by hand
 *                                                    (the step-by-step recipe): it starts at
 *                                                    "Checking from the outside…".
 *   <div data-morrow-done="example.com">             mounted by itself on load (the /r record).
 *
 * Every step on screen is a real request: the change is POST .../done/apply, the outside check is the
 * spaced re-check of make-safe.js (POST .../recheck, spacing set by the server), and the proof is
 * /r/<d>/proof.json. Steps are held on screen for a short minimum so they can be read; nothing is
 * ever shown as done before its request answered.
 *
 * The token: held in one variable of this closure, sent only to this origin's Done endpoints, never
 * written to storage, the URL or the DOM after the field is cleared, and dropped ten minutes after
 * the change (Undo then asks for it again).
 */
(function () {
  "use strict";

  var API = "/api/public/make-safe/";
  var DWELL = 650;              // the least time a step stays on screen, so it can be read
  var TOKEN_HOLD_MS = 600000;   // how long the token stays in memory after the change, for Undo
  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  function esc(v) {
    return String(v == null ? "" : v).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function enc(v) { return encodeURIComponent(String(v || "")); }
  function wait(ms) { return new Promise(function (r) { setTimeout(r, reduce ? Math.min(ms, 200) : ms); }); }
  function held(started) { var left = DWELL - (Date.now() - started); return left > 0 ? wait(left) : Promise.resolve(); }
  function store(key, value) {
    try { if (value == null) localStorage.removeItem(key); else localStorage.setItem(key, JSON.stringify(value)); } catch (e) { /* private mode */ }
  }
  function recall(key) { try { return JSON.parse(localStorage.getItem(key) || "null"); } catch (e) { return null; } }

  function call(method, url, body) {
    var opt = { method: method, credentials: "omit", cache: "no-store", headers: { Accept: "application/json" } };
    if (body) { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body); }
    return fetch(url, opt).then(function (r) {
      return r.text().then(function (t) {
        var b = null; try { b = t ? JSON.parse(t) : null; } catch (e) { b = null; }
        if (!r.ok) {
          var err = new Error((b && b.detail) || ("The server answered " + r.status + "."));
          err.status = r.status; err.body = b || {}; err.retryAfter = +(r.headers.get("Retry-After") || 0);
          throw err;
        }
        return b;
      });
    }, function () {
      var err = new Error("Morrow could not be reached. Check your connection."); err.status = 0; err.body = {}; throw err;
    });
  }

  // ── the live region, shared by every mount ────────────────────────────────
  var live = null;
  function say(text) {
    if (!live) {
      live = document.createElement("p");
      live.className = "dn-sr"; live.setAttribute("role", "status"); live.setAttribute("aria-live", "polite");
      document.body.appendChild(live);
    }
    live.textContent = "";
    setTimeout(function () { live.textContent = text; }, 30);
  }

  // ── sound: off unless the person turns it on; only ever after their own click ──
  function soundOn() { return recall("morrow.done.sound") === true; }
  function chime() {
    if (!soundOn()) return;
    try {
      var Ctx = window.AudioContext || window.webkitAudioContext; if (!Ctx) return;
      var ctx = new Ctx(), t = ctx.currentTime;
      [[659.25, 0], [987.77, 0.09]].forEach(function (n) {
        var o = ctx.createOscillator(), g = ctx.createGain();
        o.type = "sine"; o.frequency.value = n[0];
        g.gain.setValueAtTime(0.0001, t + n[1]);
        g.gain.exponentialRampToValueAtTime(0.05, t + n[1] + 0.015);
        g.gain.exponentialRampToValueAtTime(0.0001, t + n[1] + 0.32);
        o.connect(g); g.connect(ctx.destination); o.start(t + n[1]); o.stop(t + n[1] + 0.35);
      });
      setTimeout(function () { try { ctx.close(); } catch (e) { /* closed */ } }, 800);
    } catch (e) { /* no audio */ }
  }

  var LOCK = '<svg class="dn-lock" viewBox="0 0 24 24" aria-hidden="true" focusable="false">' +
    '<path class="dn-shackle" d="M7.5 11V7.5a4.5 4.5 0 0 1 9 0V11" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="square"/>' +
    '<rect x="4.5" y="11" width="15" height="10" fill="none" stroke="currentColor" stroke-width="2"/>' +
    '<rect class="dn-keyhole" x="11" y="14.5" width="2" height="3" fill="currentColor"/></svg>';

  // ── one mount ─────────────────────────────────────────────────────────────

  function Done(box, opts) {
    this.box = box; this.d = String(opts.domain || "").toLowerCase(); this.opts = opts;
    this.plan = opts.plan || null; this.token = ""; this.tokenTimer = null; this.timer = null;
    this.preview = null; this.change = recall("morrow.done.change." + this.d);
    if (this.change && Date.parse(this.change.undo_until) < Date.now()) { this.change = null; store("morrow.done.change." + this.d, null); }
    box.classList.add("dn-host");
  }

  Done.prototype.load = function () {
    var self = this;
    if (this.plan) { this.offer(); return; }
    call("GET", API + enc(this.d)).then(function (p) { self.plan = p; self.offer(); }, function () { self.box.hidden = true; });
  };

  Done.prototype.offer = function () {
    var p = this.plan || {}, oc = p.one_click;
    if (!oc) { this.box.hidden = !this.change; if (this.change) this.paintUndoOnly(); return; }
    this.box.hidden = false;
    var grade = p.grade || "";
    this.box.innerHTML =
      '<div class="dn" data-state="offer">' +
        '<p class="dn-eyebrow">Make it safe <span aria-hidden="true">/</span> ' + esc(oc.name) + '</p>' +
        '<div class="dn-offer">' +
          '<div class="dn-face"><div class="dn-grade" data-g="' + esc(grade) + '"><span class="dn-g dn-g-old">' + esc(grade || "?") + '</span></div>' + LOCK + '</div>' +
          '<div class="dn-copy"><p class="dn-lede">' + esc(oc.why) + '</p>' +
            '<p class="dn-fine">One change at ' + esc(oc.name) + ', shown to you before it is made. Undo for ' + esc(oc.undo_window_hours || 24) + ' hours.</p></div>' +
        '</div>' +
        '<div class="dn-actions"><button type="button" class="dn-btn dn-go" data-act="open">Make it safe: done</button>' +
          '<span class="dn-fine">Needs a ' + esc(oc.name) + ' API token, used once and not kept.</span></div>' +
        this.soundToggle() +
      '</div>';
    this.wire();
  };

  Done.prototype.soundToggle = function () {
    return '<p class="dn-sound"><button type="button" class="dn-link" data-act="sound" aria-pressed="' + (soundOn() ? "true" : "false") + '">Sound: ' + (soundOn() ? "on" : "off") + '</button></p>';
  };

  Done.prototype.wire = function () {
    var self = this;
    Array.prototype.forEach.call(this.box.querySelectorAll("[data-act]"), function (b) {
      if (b.hasAttribute("data-wired")) return;
      b.setAttribute("data-wired", "");
      b.addEventListener("click", function (ev) { self.act(b.getAttribute("data-act"), b, ev); });
    });
  };

  Done.prototype.act = function (what, el) {
    if (what === "open") this.openSheet();
    else if (what === "sound") { store("morrow.done.sound", !soundOn()); el.setAttribute("aria-pressed", soundOn() ? "true" : "false"); el.textContent = "Sound: " + (soundOn() ? "on" : "off"); }
    else if (what === "share") this.share(el);
    else if (what === "badge") this.badge(el);
    else if (what === "undo") this.askUndo();
    else if (what === "undo-yes") this.undo();
    else if (what === "undo-no") { var q = this.box.querySelector(".dn-undo-q"); if (q) q.hidden = true; }
    else if (what === "again") { this.plan = null; this.load(); }
    else if (what === "recheck") { el.parentNode.remove(); this.running = true; this.checkSoon(0, true); }
  };

  // ── the sheet: token, then the preview ────────────────────────────────────

  Done.prototype.sheet = function () {
    if (this.dlg && document.body.contains(this.dlg)) return this.dlg;
    var dlg = document.createElement("dialog");
    dlg.className = "dn-sheet"; dlg.setAttribute("aria-labelledby", "dn-sheet-h");
    document.body.appendChild(dlg);
    var self = this;
    dlg.addEventListener("cancel", function () { self.forget(); });
    dlg.addEventListener("click", function (ev) { if (ev.target === dlg) { self.close(); } });
    this.dlg = dlg;
    return dlg;
  };

  Done.prototype.close = function () {
    if (this.dlg && this.dlg.open) this.dlg.close();
    if (!this.running) this.forget();
    var go = this.box.querySelector(".dn-go"); if (go) go.focus();
  };

  Done.prototype.forget = function () {
    this.token = ""; if (this.tokenTimer) { clearTimeout(this.tokenTimer); this.tokenTimer = null; }
    var f = this.dlg && this.dlg.querySelector("#dn-token"); if (f) f.value = "";
  };

  Done.prototype.openSheet = function (mode) {
    var oc = (this.plan || {}).one_click || {}, tpl = oc.token_template || {}, dlg = this.sheet(), self = this;
    this.mode = mode || "change";
    var undo = this.mode === "undo";
    dlg.innerHTML =
      '<form class="dn-form" method="dialog" novalidate>' +
        '<p class="dn-eyebrow">' + (undo ? "Undo" : "Step 1 of 2") + ' <span aria-hidden="true">/</span> Your ' + esc(oc.name || "Cloudflare") + ' token</p>' +
        '<h2 id="dn-sheet-h" class="dn-h">' + (undo ? "Paste the token again to put it back" : "A token that can change DNS for this zone") + '</h2>' +
        (undo ? "" :
          '<p>Create one at Cloudflare with exactly these permissions. Morrow cannot do anything else with it.</p>' +
          '<ul class="dn-perm">' + (tpl.permissions || []).map(function (p) { return "<li>" + esc(p) + "</li>"; }).join("") +
            "<li>Zone Resources: " + esc(String(tpl.zone_resources || "").replace(/^Include > /, "Include > ")) + "</li></ul>" +
          '<p><a class="dn-btn dn-ghost" href="' + esc(tpl.url || "https://dash.cloudflare.com/profile/api-tokens") + '" target="_blank" rel="noopener noreferrer">Create the token at Cloudflare <span aria-hidden="true">&#8599;</span></a></p>') +
        '<label class="dn-label" for="dn-token">Paste the token</label>' +
        '<input class="dn-input" id="dn-token" name="dn-token" type="password" autocomplete="off" autocapitalize="off" spellcheck="false" inputmode="text" required>' +
        '<p class="dn-kept"><b>Not kept.</b> Morrow passes the token to api.cloudflare.com for this one change and forgets it. It is never stored or logged, and this page drops it ten minutes after the change.</p>' +
        '<p class="dn-err" id="dn-err" role="alert" hidden></p>' +
        '<div class="dn-actions"><button type="submit" class="dn-btn dn-go">' + (undo ? "Undo the change" : "Show me the change") + '</button>' +
          '<button type="button" class="dn-btn dn-ghost" data-close>Cancel</button></div>' +
      "</form>";
    dlg.querySelector("[data-close]").addEventListener("click", function () { self.close(); });
    dlg.querySelector("form").addEventListener("submit", function (ev) {
      ev.preventDefault();
      var v = dlg.querySelector("#dn-token").value.trim();
      if (!v) { self.sheetError({ detail: "Paste the token first." }); return; }
      self.token = v; dlg.querySelector("#dn-token").value = "";
      if (undo) self.undo(); else self.loadPreview();
    });
    if (!dlg.open) { if (dlg.showModal) dlg.showModal(); else dlg.setAttribute("open", ""); }
    dlg.querySelector("#dn-token").focus();
  };

  Done.prototype.sheetError = function (b) {
    var e = this.dlg && this.dlg.querySelector("#dn-err"); if (!e) return;
    e.hidden = false;
    e.innerHTML = "<b>" + esc(b.detail || "That did not work.") + "</b>" + (b.next_step ? " " + esc(b.next_step) : "") +
      (b.token_template && b.token_template.url && b.error === "token_scope" ? ' <a href="' + esc(b.token_template.url) + '" target="_blank" rel="noopener noreferrer">A token with the right permissions <span aria-hidden="true">&#8599;</span></a>' : "");
    say((b.detail || "That did not work.") + " " + (b.next_step || ""));
  };

  Done.prototype.busy = function (on, label) {
    var b = this.dlg && this.dlg.querySelector('button[type="submit"]'); if (!b) return;
    b.disabled = !!on; b.setAttribute("aria-busy", on ? "true" : "false");
    if (label) b.textContent = label;
  };

  Done.prototype.loadPreview = function () {
    var self = this;
    this.busy(true, "Reading the zone…");
    say("Reading the zone at Cloudflare.");
    call("POST", API + enc(this.d) + "/done/preview", { provider: "cloudflare", token: this.token })
      .then(function (pv) { self.preview = pv; self.paintPreview(); },
        function (e) { self.token = ""; self.busy(false, "Show me the change"); self.sheetError(e.body && e.body.detail ? e.body : { detail: e.message }); });
  };

  Done.prototype.paintPreview = function () {
    var pv = this.preview, dlg = this.dlg, self = this;
    if (pv.nothing_to_change) {
      dlg.innerHTML = '<div class="dn-form"><p class="dn-eyebrow">Nothing to change</p><h2 id="dn-sheet-h" class="dn-h" tabindex="-1">' + esc(pv.detail) + '</h2>' +
        '<div class="dn-actions"><button type="button" class="dn-btn dn-go" data-check>Check from the outside</button><button type="button" class="dn-btn dn-ghost" data-close>Close</button></div></div>';
      dlg.querySelector("[data-close]").addEventListener("click", function () { self.close(); });
      dlg.querySelector("[data-check]").addEventListener("click", function () { self.forget(); dlg.close(); self.run(null); });
      dlg.querySelector("h2").focus();
      return;
    }
    var c = pv.change;
    var rows = (c.records || []).map(function (r) {
      return '<tr><td>' + esc(r.type) + '</td><td class="dn-mono">' + esc(r.content) + '</td><td><span class="dn-from">' + esc(r.from) + '</span> <span aria-hidden="true">&#8594;</span><span class="dn-sr"> to </span> <span class="dn-to">' + esc(r.to) + "</span></td></tr>";
    }).join("");
    dlg.innerHTML =
      '<div class="dn-form">' +
        '<p class="dn-eyebrow">Step 2 of 2 <span aria-hidden="true">/</span> The change</p>' +
        '<h2 id="dn-sheet-h" class="dn-h" tabindex="-1">We will change: ' + esc(c.title) + ".</h2>" +
        '<p class="dn-nothing">' + esc(c.nothing_else) + "</p>" +
        (rows ? '<table class="dn-table"><caption class="dn-sr">Records that change</caption><thead><tr><th scope="col">Type</th><th scope="col">Points at</th><th scope="col">Proxy status</th></tr></thead><tbody>' + rows + "</tbody></table>" : "") +
        '<p class="dn-label">What this means</p><ul class="dn-cons">' + (c.consequences || []).map(function (x) { return "<li>" + esc(x) + "</li>"; }).join("") + "</ul>" +
        (pv.note ? '<p class="dn-note">' + esc(pv.note) + "</p>" : "") +
        '<p class="dn-fine">Zone ' + esc(pv.zone) + ". " + esc(c.propagation) + " Undo stays available for " + esc(pv.undo_window_hours) + " hours.</p>" +
        '<p class="dn-err" id="dn-err" role="alert" hidden></p>' +
        '<div class="dn-actions"><button type="button" class="dn-btn dn-go" data-confirm>Confirm: make it safe</button>' +
          '<button type="button" class="dn-btn dn-ghost" data-close>Cancel</button></div>' +
      "</div>";
    dlg.querySelector("[data-close]").addEventListener("click", function () { self.close(); });
    dlg.querySelector("[data-confirm]").addEventListener("click", function () { dlg.close(); self.run(pv); });
    dlg.querySelector("h2").focus();
    say("Preview. We will change " + c.title + ". Nothing else. Confirm to make the change.");
  };

  // ── the sequence ──────────────────────────────────────────────────────────

  Done.prototype.frame = function (byHand) {
    var p = this.plan || {}, grade = this.opts.grade || p.grade || "", kx = this.opts.kx || p.key_exchange || "classical";
    this.box.hidden = false;
    this.box.innerHTML =
      '<div class="dn" data-state="running">' +
        '<p class="dn-eyebrow">Make it safe <span aria-hidden="true">/</span> ' + esc(byHand ? "your change" : ((p.one_click || {}).name || "Cloudflare")) + '</p>' +
        '<div class="dn-run">' +
          '<div class="dn-face"><div class="dn-grade" data-g="' + esc(grade) + '"><span class="dn-g dn-g-old">' + esc(grade || "?") + '</span><span class="dn-g dn-g-new" aria-hidden="true"></span></div>' + LOCK + '</div>' +
          '<ol class="dn-steps">' +
            '<li data-s="change" data-state="' + (byHand ? "done" : "active") + '"><span class="dn-tick" aria-hidden="true"></span><div><p class="dn-step">' + (byHand ? "You made the change." : "Changing the setting…") + '</p><p class="dn-meta"></p></div></li>' +
            '<li data-s="check" data-state="' + (byHand ? "active" : "idle") + '"><span class="dn-tick" aria-hidden="true"></span><div><p class="dn-step">Checking from the outside…</p>' +
              '<p class="dn-readout" aria-hidden="true"><span class="dn-k">key exchange</span> <span class="dn-kx" data-pq="false">' + esc(kx) + '</span><span class="dn-scan"></span></p><p class="dn-meta"></p></div></li>' +
            '<li data-s="safe" data-state="idle"><span class="dn-tick" aria-hidden="true"></span><div><p class="dn-step dn-final" tabindex="-1">Quantum-safe.</p><p class="dn-meta"></p></div></li>' +
          "</ol>" +
        "</div>" +
        '<div class="dn-proof" hidden></div>' +
        this.soundToggle() +
      "</div>";
    this.wire();
  };

  Done.prototype.step = function (name, state, meta, label) {
    var li = this.box.querySelector('[data-s="' + name + '"]'); if (!li) return;
    li.setAttribute("data-state", state);
    if (label != null) li.querySelector(".dn-step").textContent = label;
    if (meta != null) li.querySelector(".dn-meta").innerHTML = meta;
  };

  Done.prototype.run = function (pv) {
    var self = this, t0 = Date.now();
    this.running = true;
    this.frame(!pv && this.opts.byHand);
    if (!pv) {
      this.step("change", "done", this.opts.byHand ? "" : "Nothing to change at Cloudflare.", this.opts.byHand ? "You made the change." : "Already set at Cloudflare.");
      this.checkSoon(0, true);
      return;
    }
    say("Changing the setting at Cloudflare.");
    if (this.box.scrollIntoView) this.box.scrollIntoView({ block: "nearest", behavior: reduce ? "auto" : "smooth" });
    call("POST", API + enc(this.d) + "/done/apply", { preview_id: pv.preview_id, token: this.token })
      .then(function (out) {
        return held(t0).then(function () {
          self.change = { change_id: out.change_id, undo_until: out.undo_until, kind: out.kind, title: pv.change.title };
          store("morrow.done.change." + self.d, self.change);
          self.propagation = out.propagation_seconds || 300;
          // Keep the token for Undo for a while, in this variable only.
          self.tokenTimer = setTimeout(function () { self.token = ""; }, TOKEN_HOLD_MS);
          self.step("change", "done", esc(pv.change.title) + ". Changed at " + esc(out.applied_at.slice(11, 19)) + " UTC.", "Changed the setting.");
          say("Changed. " + pv.change.title + ". Now checking from the outside.");
          self.checkSoon(0, true);
        });
      }, function (e) {
        return held(t0).then(function () {
          self.running = false; self.token = "";
          var b = e.body || {};
          self.step("change", "fail", "<b>" + esc(b.detail || e.message) + "</b> " + esc(b.next_step || "Nothing was changed."), "The setting was not changed.");
          self.failActions();
          say("The setting was not changed. " + (b.detail || e.message) + " " + (b.next_step || ""));
        });
      });
  };

  Done.prototype.failActions = function () {
    var run = this.box.querySelector(".dn-run");
    run.insertAdjacentHTML("afterend", '<div class="dn-actions"><button type="button" class="dn-btn dn-go" data-act="again">Try again</button>' +
      '<a class="dn-btn dn-ghost" href="/' + enc(this.d) + '#make-safe">The step-by-step recipe</a></div>');
    this.wire();
  };

  Done.prototype.checkSoon = function (seconds, start) {
    var self = this;
    if (this.timer) clearTimeout(this.timer);
    var li = this.box.querySelector('[data-s="check"]');
    if (li && li.getAttribute("data-state") !== "active") this.step("check", "active");
    this.timer = setTimeout(function () {
      if (!document.body.contains(self.box)) return;
      if (document.visibilityState === "hidden") {
        document.addEventListener("visibilitychange", function again() { if (document.visibilityState === "visible") { document.removeEventListener("visibilitychange", again); self.check(start); } });
        return;
      }
      self.check(start);
    }, Math.max(0, seconds) * 1000);
    if (seconds > 0) this.countdown(seconds);
  };

  Done.prototype.countdown = function (seconds) {
    var self = this, end = Date.now() + seconds * 1000;
    if (this.tick) clearInterval(this.tick);
    this.tick = setInterval(function () {
      var left = Math.max(0, Math.round((end - Date.now()) / 1000));
      var n = self.box.querySelector(".dn-next"); if (n) n.textContent = left > 0 ? "Next check in " + (left < 90 ? left + " s" : Math.round(left / 60) + " min") + "." : "Checking now.";
      if (left <= 0) clearInterval(self.tick);
    }, 1000);
  };

  Done.prototype.check = function (start) {
    var self = this, t0 = Date.now(), ro = this.box.querySelector(".dn-readout");
    if (ro) ro.setAttribute("data-probing", "true");
    say("Checking " + this.d + " from the outside.");
    call("POST", API + enc(this.d) + "/recheck", { start: !!start })
      .then(function (out) {
        return held(t0).then(function () {
          if (ro) ro.removeAttribute("data-probing");
          var w = out.watch || {}, r = out.result || {};
          var kxEl = self.box.querySelector(".dn-kx");
          if (kxEl && (r.key_exchange || w.key_exchange)) { kxEl.textContent = r.key_exchange || w.key_exchange; kxEl.setAttribute("data-pq", r.post_quantum || w.status === "live" ? "true" : "false"); }
          if (w.status === "live") { self.safe(out); return; }
          var cache = self.propagation ? " Resolvers can keep the old DNS answer for up to " + Math.round(self.propagation / 60) + " min after the change." : "";
          if (w.status === "error") self.step("check", "active", "That check did not complete: " + esc(w.last_error || "") + ' <span class="dn-next"></span>');
          else self.step("check", "active", "Still " + esc(w.key_exchange || "classical") + " (check " + esc(w.attempts) + ")." + esc(cache) + ' <span class="dn-next"></span>');
          if (w.auto) self.checkSoon(w.next_check_in || 30, false);
          else self.stuck(w);
        });
      }, function (e) {
        if (ro) ro.removeAttribute("data-probing");
        var b = e.body || {};
        if (e.status === 429 && b.watch) { self.step("check", "active", "Morrow spaces its checks so your server is never hammered. " + '<span class="dn-next"></span>'); self.checkSoon(e.retryAfter || b.watch.next_check_in || 30, false); return; }
        self.running = false;
        self.step("check", "fail", "<b>" + esc(b.detail || e.message) + "</b>", "The outside check could not run.");
        self.failActions();
      });
  };

  Done.prototype.stuck = function (w) {
    this.running = false;
    var tls = this.preview && this.preview.note;
    this.step("check", "fail", "Still " + esc(w.key_exchange || "classical") + " after " + esc(w.attempts) + " checks. " +
      (tls ? esc(tls) + " " : "") + "Purge Cloudflare's cache, check SSL/TLS > Edge Certificates > TLS 1.3 is On, then check again.",
      "Still classical from the outside.");
    var run = this.box.querySelector(".dn-run");
    run.insertAdjacentHTML("afterend", '<div class="dn-actions"><button type="button" class="dn-btn dn-go" data-act="recheck">Check again</button>' +
      (this.change ? '<button type="button" class="dn-btn dn-ghost" data-act="undo">Undo the change</button>' : "") + "</div>");
    this.wire();
    say("Still classical from the outside after " + w.attempts + " checks.");
  };

  Done.prototype.safe = function (out) {
    var self = this, r = out.result || {}, w = out.watch || {};
    this.running = false;
    this.step("check", "done", "Seen from Morrow at " + esc(String(w.last_checked_at || "").slice(11, 19)) + " UTC, check " + esc(w.attempts || 1) + ".", "Checked from the outside.");
    var dn = this.box.querySelector(".dn"), g = this.box.querySelector(".dn-grade");
    var newGrade = r.grade || "A";
    g.querySelector(".dn-g-new").textContent = newGrade;
    requestAnimationFrame(function () {
      dn.setAttribute("data-state", "safe");
      g.setAttribute("data-g", newGrade);
      g.classList.add("is-flipped");
      self.step("safe", "done", esc(self.d) + " negotiates " + esc(r.key_exchange || w.key_exchange || "post-quantum key exchange") + " with every visitor that supports it.");
    });
    chime();
    say(this.d + " is quantum-safe. Grade " + newGrade + ". The signed proof follows.");
    setTimeout(function () { var f = self.box.querySelector(".dn-final"); if (f) f.focus(); }, reduce ? 0 : 420);
    if (this.opts.onLive) { try { this.opts.onLive(out); } catch (e) { /* the page's own problem */ } }
    setTimeout(function () { self.proof(out.proof_url || ("/r/" + enc(self.d) + "/proof")); }, reduce ? 0 : 700);
  };

  // ── the proof card ────────────────────────────────────────────────────────

  Done.prototype.proof = function (page) {
    var self = this, box = this.box.querySelector(".dn-proof"), d = this.d, base = location.origin;
    call("GET", "/r/" + enc(d) + "/proof.json").then(function (env) {
      var doc = env.document || {}, sigs = (env.signatures || []).map(function (s) { return s.alg; }).join(" and ");
      paint("quantum-safe since " + esc(String(doc.safe_since || "").slice(0, 10)), esc(doc.statement || ""), sigs ? "Signed with " + esc(sigs) + ". Anyone can check both signatures." : "");
    }, function (e) {
      paint("quantum-safe", "", e.status === 503 ? "This server cannot sign proofs right now; the proof page shows the record unsigned." : "The proof page has the record.");
    });
    function paint(head, statement, signed) {
      var badge = "[![quantum-readiness grade](" + base + "/api/public/badge/" + d + ".svg)](" + base + "/r/" + d + "/proof)";
      self.badgeText = badge; self.proofUrl = base + page;
      var undo = self.change && Date.parse(self.change.undo_until) > Date.now();
      box.innerHTML =
        '<p class="dn-eyebrow">Signed proof</p>' +
        '<p class="dn-proof-h"><a href="' + esc(page) + '">' + esc(d) + "</a>: " + head + "</p>" +
        (statement ? '<p class="dn-fine">' + statement + "</p>" : "") + (signed ? '<p class="dn-fine">' + signed + "</p>" : "") +
        '<div class="dn-actions">' +
          '<button type="button" class="dn-btn dn-go" data-act="share">Share</button>' +
          '<button type="button" class="dn-btn dn-ghost" data-act="badge" aria-expanded="false" aria-controls="dn-badge">Badge snippet</button>' +
          '<a class="dn-btn dn-ghost" href="/r/' + enc(d) + '/proof.json" download="' + esc(d) + '-quantum-safe-proof.json">Download proof</a>' +
        "</div>" +
        '<pre class="dn-snippet" id="dn-badge" tabindex="0" hidden>' + esc(badge) + "</pre>" +
        (undo ? '<p class="dn-undo"><button type="button" class="dn-link" data-act="undo">Undo this change</button> <span class="dn-fine">until ' + esc(self.change.undo_until.slice(0, 16).replace("T", " ")) + ' UTC</span></p>' +
          '<div class="dn-undo-q" hidden><p>Put back: ' + esc(self.change.title.replace("from DNS only to Proxied", "from Proxied to DNS only").replace("from Off to On", "from On to Off")) + "?</p>" +
          '<div class="dn-actions"><button type="button" class="dn-btn dn-warn" data-act="undo-yes">Undo</button><button type="button" class="dn-btn dn-ghost" data-act="undo-no">Keep it safe</button></div><p class="dn-err" role="alert" hidden></p></div>' : "");
      box.hidden = false;
      requestAnimationFrame(function () { box.classList.add("is-in"); });
      self.wire();
    }
  };

  Done.prototype.share = function (el) {
    var url = this.proofUrl, d = this.d;
    if (navigator.share) { navigator.share({ title: d + " is quantum-safe", text: d + " is quantum-safe: signed proof", url: url }).catch(function () { /* dismissed */ }); return; }
    this.copy(url, el, "Link copied");
  };

  Done.prototype.badge = function (el) {
    var pre = this.box.querySelector("#dn-badge");
    pre.hidden = false; el.setAttribute("aria-expanded", "true");
    this.copy(this.badgeText, el, "Snippet copied");
  };

  Done.prototype.copy = function (text, el, label) {
    var orig = el.getAttribute("data-label") || el.textContent;
    el.setAttribute("data-label", orig);
    var ok = function () { el.textContent = label; say(label + "."); setTimeout(function () { el.textContent = orig; }, 1800); };
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(ok, function () { el.textContent = "Select and copy"; });
    else el.textContent = "Select and copy";
  };

  // ── undo ──────────────────────────────────────────────────────────────────

  Done.prototype.askUndo = function () {
    var q = this.box.querySelector(".dn-undo-q");
    if (q) { q.hidden = false; var y = q.querySelector('[data-act="undo-yes"]'); if (y) y.focus(); return; }
    this.undo();
  };

  Done.prototype.undo = function () {
    var self = this;
    if (!this.change) return;
    if (!this.token) { this.openSheet("undo"); return; }
    if (this.dlg && this.dlg.open) this.busy(true, "Putting it back…");
    call("POST", API + enc(this.d) + "/done/undo", { change_id: this.change.change_id, token: this.token })
      .then(function (out) {
        self.forget(); if (self.dlg && self.dlg.open) self.dlg.close();
        self.change = null; store("morrow.done.change." + self.d, null);
        self.box.innerHTML = '<div class="dn" data-state="undone"><p class="dn-eyebrow">Undone</p><p class="dn-lede" tabindex="-1">' + esc(out.detail) + "</p>" +
          '<div class="dn-actions"><button type="button" class="dn-btn dn-ghost" data-act="again">Back to Make it safe</button></div></div>';
        self.wire();
        self.box.querySelector(".dn-lede").focus();
        say(out.detail);
      }, function (e) {
        self.token = "";
        var b = e.body && e.body.detail ? e.body : { detail: e.message };
        if (self.dlg && self.dlg.open) { self.busy(false, "Undo the change"); self.sheetError(b); return; }
        var err = self.box.querySelector(".dn-undo-q .dn-err");
        if (err) { err.hidden = false; err.textContent = b.detail + (b.next_step ? " " + b.next_step : ""); }
        if (e.status === 400 || e.status === 401 || e.status === 403) self.openSheet("undo");
      });
  };

  Done.prototype.paintUndoOnly = function () {
    var c = this.change;
    this.box.innerHTML = '<div class="dn" data-state="safe"><p class="dn-eyebrow">Make it safe <span aria-hidden="true">/</span> your last change</p>' +
      '<p class="dn-lede">' + esc(c.title) + '.</p><p class="dn-undo"><button type="button" class="dn-link" data-act="undo">Undo this change</button> <span class="dn-fine">until ' + esc(c.undo_until.slice(0, 16).replace("T", " ")) + " UTC</span></p></div>";
    this.wire();
  };

  // ── public ────────────────────────────────────────────────────────────────

  var mounts = [];
  function mount(box, opts) {
    if (!box || !opts || !opts.domain) return null;
    for (var i = 0; i < mounts.length; i++) if (mounts[i].box === box && mounts[i].d === String(opts.domain).toLowerCase()) { if (opts.plan) { mounts[i].plan = opts.plan; if (!mounts[i].running) mounts[i].offer(); } return mounts[i]; }
    var m = new Done(box, opts); mounts.push(m); m.load(); return m;
  }
  function watch(box, opts) {
    if (!box || !opts || !opts.domain) return null;
    var m = new Done(box, { domain: opts.domain, grade: opts.grade, kx: opts.kx, onLive: opts.onLive, byHand: true, plan: opts.plan || {} });
    mounts.push(m); m.run(null); return m;
  }
  function auto() {
    Array.prototype.forEach.call(document.querySelectorAll("[data-morrow-done]"), function (el) {
      mount(el, { domain: el.getAttribute("data-morrow-done") });
    });
  }
  window.addEventListener("pagehide", function () { mounts.forEach(function (m) { m.forget(); }); });
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", auto); else auto();
  window.MorrowDone = { mount: mount, watch: watch };
})();
