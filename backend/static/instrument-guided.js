/*
 * Guided mode: three questions, one answer (instrument.js calls MorrowGuided.switchHtml/start).
 *
 * The front page keeps everything it has. A quiet switch beside the domain box ("Browse everything"
 * / "Just answer 3 questions") turns this on; it is remembered on this device (localStorage) and can
 * be linked as /?guided=1 (/?guided=0 turns it off). Public, no account.
 *
 *   1. What's your website or company domain?   (a supplier's works too)
 *   2. Who are you?                               I run it / I'm checking a supplier / I report to the board
 *   3. What does it carry?                        the Shelf-Life kinds the risk sentence uses; Not sure = its default
 *
 * Every question can be skipped. Then one screen: the grade, the risk sentence for that kind of
 * data, the deadline, and exactly one next action for that role (services/guided.py, ROLE_ACTIONS).
 * The check is the public grade's own (GET /api/public/grade/<domain>, with its budgets and opt-out);
 * the answer is GET /api/public/guided/<domain>. Same origin only, no inline script or style.
 */
(function () {
  "use strict";
  function I() { return window.MorrowIns; }
  function $(s, r) { return (r || document).querySelector(s); }
  function esc(v) { return I().esc(v); }
  function enc(v) { return encodeURIComponent(v); }
  var KEY = "morrow_guided";
  var MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  function when(iso) { var d = new Date(iso); return !iso || isNaN(d) ? "" : d.getUTCDate() + " " + MONTHS[d.getUTCMonth()] + " " + d.getUTCFullYear(); }

  /* Who is asking -> the one action. services/guided.py keeps the same map (ROLE_ACTIONS). */
  var ROLES = [
    { id: "it", label: "I run it", hint: "IT or security: you can change the server", action: "Make it safe" },
    { id: "supplier", label: "I’m checking a supplier", hint: "It’s someone else’s site you depend on", action: "Send them this note" },
    { id: "board", label: "I report to the board or leadership", hint: "They want the answer and the date", action: "Print the one-page summary" }
  ];
  var DATA = [
    { id: "personal", label: "Personal data", hint: "Names, emails, accounts" },
    { id: "health", label: "Health records", hint: "Patients, prescriptions, care" },
    { id: "financial", label: "Payments or finance", hint: "Cards, accounts, transactions" },
    { id: "auth", label: "Passwords and keys", hint: "Logins, API keys, tokens" },
    { id: "trade", label: "Trade secrets", hint: "Designs, plans, source code" },
    { id: "", label: "Not sure", hint: "Morrow assumes personal data" }
  ];

  function stored() { try { return localStorage.getItem(KEY); } catch (e) { return null; } }
  function store(v) { try { localStorage.setItem(KEY, v); } catch (e) { /* private mode: the URL still carries it */ } }
  /* On when the URL says ?guided=1, or this device chose it; ?guided=0 turns it off. Off by default. */
  function on() {
    var p = I().param("guided");
    if (p === "1") { store("1"); return true; }
    if (p === "0") { store("0"); return false; }
    return stored() === "1";
  }
  function lastDomain() {
    try {
      var r = JSON.parse(localStorage.getItem("morrow_recent") || "[]").filter(function (x) { return x.kind === "domain"; })[0];
      return r && r.id ? r.id : "";
    } catch (e) { return ""; }
  }

  function switchHtml(active) {
    return '<div class="gd-switch" role="group" aria-label="How to use Morrow">' +
      '<button type="button" data-guided="0" aria-pressed="' + !active + '">Browse everything</button>' +
      '<button type="button" data-guided="1" aria-pressed="' + !!active + '">Just answer 3 questions</button></div>';
  }
  function bindSwitch(root) {
    Array.prototype.forEach.call((root || document).querySelectorAll(".gd-switch [data-guided]"), function (b) {
      b.addEventListener("click", function () { set(b.getAttribute("data-guided") === "1"); });
    });
  }
  function set(v) {
    store(v ? "1" : "0");
    I().setParam("guided", v ? "1" : null, true);
    I().setParam("step", null);
    location.reload();
  }

  /* ── the three questions ── */
  var A = { domain: "", role: "", data: null, step: 1, dir: 1 };
  var REDUCED = !!(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches);
  var root = null;

  function frame() {
    document.body.classList.add("gd-on");
    I().setView("grade", "Three questions");
    root.innerHTML = '<div class="gd" id="gd">' +
      '<div class="gd-bar"><ol class="gd-prog" id="gd-prog" aria-label="Progress"></ol>' + switchHtml(true) + "</div>" +
      '<div class="gd-stage" id="gd-stage"></div></div>';
    bindSwitch(root);
  }
  function progress() {
    var p = $("#gd-prog"); if (!p) return;
    var n = A.step > 3 ? 3 : A.step;
    p.innerHTML = [1, 2, 3].map(function (i) {
      return '<li data-s="' + (i < A.step ? "done" : i === n && A.step <= 3 ? "now" : A.step > 3 ? "done" : "next") + '"' + (i === n && A.step <= 3 ? ' aria-current="step"' : "") + '><span class="sr-only">Question </span>' + i + '<span class="sr-only"> of 3</span></li>';
    }).join("") + '<li class="gd-prog-t" aria-hidden="true">' + (A.step > 3 ? "Your answer" : A.step + " / 3") + "</li>";
  }
  function show(html, focusSel) {
    var st = $("#gd-stage");
    st.classList.remove("gd-in", "gd-back-in"); void st.offsetWidth;
    st.innerHTML = html;
    st.classList.add(A.dir < 0 ? "gd-back-in" : "gd-in");
    progress();
    var f = $(focusSel || "h1", st); if (f) f.focus({ preventScroll: false });
    window.scrollTo(0, 0);
  }
  function nav(back, skipLabel) {
    return '<div class="gd-nav">' + (back ? '<button type="button" class="gd-back" id="gd-back">&larr; Back</button>' : "<span></span>") +
      (skipLabel ? '<button type="button" class="gd-skip" id="gd-skip">' + esc(skipLabel) + "</button>" : "") + "</div>";
  }
  function bindNav(onSkip) {
    var b = $("#gd-back"); if (b) b.addEventListener("click", function () { go(A.step - 1); });
    var s = $("#gd-skip"); if (s) s.addEventListener("click", onSkip);
  }
  function go(step) {
    A.dir = step < A.step ? -1 : 1;
    A.step = Math.max(1, Math.min(4, step));
    if (A.step === 1) return q1();
    if (A.step === 2) return q2();
    if (A.step === 3) return q3();
    return result();
  }

  function q1() {
    var fallback = lastDomain() || "example.com";
    show('<form class="gd-q" id="gd-f1" novalidate><h1 class="gd-h" tabindex="-1" id="gd-h1"><label for="gd-domain">What&rsquo;s your website or company domain?</label></h1>' +
      '<div class="gd-field"><input id="gd-domain" type="text" inputmode="url" autocomplete="url" autocapitalize="none" spellcheck="false" placeholder="your-company.com" value="' + esc(A.domain) + '" aria-describedby="gd-d-hint"></div>' +
      '<p class="gd-hint" id="gd-d-hint" aria-live="polite">Checking a supplier? Type theirs.</p>' +
      '<div class="gd-go"><button type="submit" class="i-btn solid gd-next">Next</button><span class="gd-enter" aria-hidden="true">or press Enter</span></div></form>' +
      nav(false, "Skip: use " + fallback), "#gd-domain");
    var inp = $("#gd-domain"), hint = $("#gd-d-hint");
    inp.addEventListener("input", function () {
      var d = I().asDomain(inp.value);
      if (d) { hint.setAttribute("data-tone", "ok"); hint.textContent = "Looks right: " + d + ". Press Enter."; }
      else { hint.removeAttribute("data-tone"); hint.textContent = "Checking a supplier? Type theirs."; }
    });
    $("#gd-f1").addEventListener("submit", function (e) {
      e.preventDefault();
      var v = $("#gd-domain").value, d = I().asDomain(v), h = $("#gd-d-hint");
      if (!d) { h.setAttribute("data-tone", "no"); h.textContent = v.trim() ? "That doesn’t look like a domain. Type one like example.com." : "Type a domain like example.com, or skip to use " + fallback + "."; $("#gd-domain").focus(); return; }
      A.domain = d; go(2);
    });
    bindNav(function () { A.domain = fallback; go(2); });
  }
  function choices(list, current, name) {
    return '<div class="gd-choices" role="group" aria-labelledby="gd-h1">' + list.map(function (c) {
      return '<button type="button" class="gd-choice" data-' + name + '="' + esc(c.id) + '" aria-pressed="' + (current === c.id) + '"><span class="gd-c-l">' + esc(c.label) + '</span><span class="gd-c-h">' + esc(c.hint) + "</span></button>";
    }).join("") + "</div>";
  }
  /* A choice lights at once, then the next question follows (at once under reduced motion). */
  function chosen(b, next) {
    Array.prototype.forEach.call(b.parentNode.querySelectorAll("button"), function (x) { x.setAttribute("aria-pressed", String(x === b)); });
    if (REDUCED) { next(); return; }
    b.classList.add("gd-picked");
    setTimeout(next, 140);
  }
  function q2() {
    show('<div class="gd-q"><p class="gd-for">' + esc(A.domain) + '</p><h1 class="gd-h" tabindex="-1" id="gd-h1">Who are you?</h1>' + choices(ROLES, A.role, "role") + "</div>" + nav(true, "Skip: I run it"));
    Array.prototype.forEach.call(document.querySelectorAll("[data-role]"), function (b) {
      b.addEventListener("click", function () { A.role = b.getAttribute("data-role"); chosen(b, function () { go(3); }); });
    });
    var first = $('[data-role="' + (A.role || "it") + '"]'); if (first) first.focus();
    bindNav(function () { A.role = "it"; go(3); });
  }
  function q3() {
    show('<div class="gd-q"><p class="gd-for">' + esc(A.domain) + '</p><h1 class="gd-h" tabindex="-1" id="gd-h1">What does it carry?</h1>' +
      '<p class="gd-hint">The most sensitive thing sent to or from it. It sets how long that data must stay private.</p>' + choices(DATA, A.data, "data") + "</div>" + nav(true, "Skip: not sure"));
    Array.prototype.forEach.call(document.querySelectorAll("[data-data]"), function (b) {
      b.addEventListener("click", function () { A.data = b.getAttribute("data-data"); chosen(b, function () { go(4); }); });
    });
    var first = $('[data-data="' + (A.data == null ? "personal" : A.data) + '"]'); if (first) first.focus();
    bindNav(function () { A.data = ""; go(4); });
  }

  /* ── the answer ── */
  function result() {
    var role = A.role || "it", d = A.domain;
    show('<div class="gd-res" id="gd-res" aria-live="polite" aria-busy="true"><p class="gd-for">' + esc(d) + '</p>' +
      '<h1 class="gd-h" tabindex="-1" id="gd-h1">Checking ' + esc(d) + ' now&hellip;</h1>' +
      '<p class="gd-hint">One TLS handshake to port 443, the same check as everywhere on Morrow. Usually a few seconds.</p></div>' + nav(true, ""));
    bindNav();
    I().getJSON("/api/public/grade/" + enc(d), { cache: "no-store", timeout: 60000 })
      .then(function () {
        return I().getJSON("/api/public/guided/" + enc(d) + "?role=" + enc(role) + "&data=" + enc(A.data || ""), { cache: "no-store" });
      })
      .then(paint)
      .catch(function (e) {
        var msg = e.status === 429 ? "Too many checks from here just now." + (e.retryAfter ? " Try again in " + e.retryAfter + " seconds." : " Try again in a minute.")
          : e.status === 403 ? (e.message || "This domain has opted out of Morrow’s checks.")
          : e.status === 400 ? (e.message || "That domain could not be checked.")
          : (e.message || "The check did not finish.");
        show('<div class="gd-res" id="gd-res" aria-live="polite"><p class="gd-for">' + esc(d) + '</p><h1 class="gd-h" tabindex="-1" id="gd-h1">No answer yet</h1>' +
          '<p class="gd-say">' + esc(msg) + '</p><div class="gd-go"><button type="button" class="i-btn solid" id="gd-retry">Try again</button></div>' +
          '<p class="gd-more"><button type="button" id="gd-again">Start over</button><a href="/r/' + enc(d) + '">See the full record</a><button type="button" data-guided="0" class="gd-out">Browse everything</button></p></div>');
        $("#gd-retry").addEventListener("click", result);
        $("#gd-again").addEventListener("click", restart);
        bindOut();
      });
  }
  function deadlineHtml(dl) {
    if (!dl) return "";
    var big = dl.status === "overdue" ? "Overdue since " + dl.since : dl.status === "due" ? "Must be safe now" : dl.status === "ahead" ? "Must be safe by " + dl.value : dl.status === "met" ? "Deadline met" : "No deadline yet";
    return '<div class="gd-dl" data-s="' + esc(dl.status) + '"><p class="gd-k">Deadline, an estimate</p><p class="gd-dl-v">' + esc(big) + "</p>" +
      '<p class="gd-dl-l">' + esc(dl.label || "") + (dl.basis ? " " + esc(dl.basis.text) + "." : "") + "</p></div>";
  }
  function paint(R) {
    var a = R.action || {}, safe = !!R.safe;
    var primary = a.kind === "make_safe" ? '<a class="i-btn solid gd-act" id="gd-act" href="' + esc(a.href) + '">' + esc(a.label) + "</a>"
      : a.kind === "note" ? '<button type="button" class="i-btn solid gd-act" id="gd-act">' + esc(a.label) + "</button>"
      : a.kind === "summary" ? '<button type="button" class="i-btn solid gd-act" id="gd-act">' + esc(a.label) + "</button>"
      : '<a class="i-btn solid gd-act" id="gd-act" href="' + esc(a.href || R.record) + '">' + esc(a.label || "See the full record") + "</a>";
    var extra = a.kind === "note" ? '<div class="gd-note" id="gd-note" hidden><pre id="gd-note-t">' + esc(a.text) + '</pre><p class="gd-hint" id="gd-note-s" aria-live="polite"></p></div>' : "";
    var account = a.kind === "summary" ? '<p class="gd-hint gd-acct">' + esc(a.detail) + ' <a href="' + esc(a.account_href || "/ui/") + '">Sign in or create an account</a>.</p>' : '<p class="gd-hint">' + esc(a.detail || "") + "</p>";
    show('<article class="gd-res" id="gd-res" aria-live="polite">' +
      '<p class="gd-for">' + esc(R.domain) + " &middot; checked " + esc(when(R.checked_at)) + (R.key_exchange ? " &middot; " + esc(R.key_exchange) : "") + "</p>" +
      '<div class="gd-verdict" data-safe="' + safe + '"><span class="grade gd-grade" data-g="' + esc(R.grade || "") + '" aria-hidden="true">' + esc(R.grade || "-") + "</span>" +
      '<h1 class="gd-h gd-v" tabindex="-1" id="gd-h1"><span class="gd-ic" aria-hidden="true">' + (safe ? "&check;" : "!") + "</span>" +
      (safe ? "Quantum-safe" : "Not quantum-safe yet") + '<span class="sr-only">: grade ' + esc(R.grade || "unknown") + "</span></h1></div>" +
      '<p class="gd-say">' + esc(R.sentence) + "</p>" +
      deadlineHtml(R.deadline) +
      // #gd-make-safe: where the Make it safe action renders on the answer (the hook in instrument.js).
      '<div class="gd-go" id="' + (a.kind === "make_safe" ? "gd-make-safe" : "gd-action") + '">' + primary + "</div>" + account + extra +
      '<p class="gd-more"><a href="' + esc(R.record) + '">See the full record</a><button type="button" id="gd-again">Start over</button><button type="button" data-guided="0" class="gd-out">Browse everything</button></p>' +
      '<p class="gd-fine">' + esc(R.assumption || "") + " The years are an estimate from the " + '<a href="' + esc((R.estimate || {}).source_url || "/threat") + '" rel="noopener">' + esc((R.estimate || {}).source_label || "expert survey") + "</a>.</p>" +
      "</article>");
    var act = $("#gd-act");
    var res = $("#gd-res"); if (res && !REDUCED) res.classList.add("gd-reveal");
    if (a.kind === "make_safe" && I().makeSafeRendered) I().makeSafeRendered($("#gd-make-safe"), { source: "guided", domain: R.domain });
    if (a.kind === "note") act.addEventListener("click", function () {
      var box = $("#gd-note"); box.hidden = false;
      var s = $("#gd-note-s");
      if (navigator.clipboard) navigator.clipboard.writeText(a.text).then(function () { s.textContent = "Copied. Paste it into an email to them; Morrow sends nothing."; }, function () { s.textContent = "Select the note and copy it. Morrow sends nothing."; });
      else s.textContent = "Select the note and copy it. Morrow sends nothing.";
    });
    if (a.kind === "summary") act.addEventListener("click", function () { window.print(); });
    $("#gd-again").addEventListener("click", restart);
    bindOut();
  }
  function bindOut() {
    Array.prototype.forEach.call(document.querySelectorAll(".gd-out[data-guided]"), function (b) { b.addEventListener("click", function () { set(false); }); });
  }
  function restart() { A = { domain: "", role: "", data: null, step: 1 }; go(1); }

  function start(box) {
    root = box;
    frame();
    go(1);
  }

  window.MorrowGuided = { on: on, start: start, switchHtml: switchHtml, bindSwitch: bindSwitch, ROLES: ROLES, DATA: DATA };
})();
