/*
 * Watch mode, domain claims and /about-scanner for the instrument (instrument.js calls in here).
 *
 *   MorrowWatch.domain(d, r)     the "Watch" panel on /<domain>: watch it, claim it, the owner's tools
 *   MorrowWatch.services(d, tp)  the outside services, once read, for the owner's fix plan
 *   MorrowWatch.watching()       /watching: what changed, what you watch, where alerts go
 *   MorrowWatch.aboutScanner()   /about-scanner: what the checker sends, how often, how to stop it
 *
 * Every alert channel here is one a person sets up for themselves: this browser (Web Push), a
 * webhook, a private feed. Nothing is ever emailed. Same origin only; no inline script or style.
 */
(function () {
  "use strict";
  function I() { return window.MorrowIns; }

  function send(method, url, body) {
    var h = { Accept: "application/json" };
    var tok = I().token;
    if (tok) h.Authorization = "Bearer " + tok;
    if (body !== undefined) h["Content-Type"] = "application/json";
    return fetch(url, { method: method, headers: h, credentials: "same-origin", cache: "no-store",
      body: body === undefined ? undefined : JSON.stringify(body) })
      .then(function (r) {
        return r.text().then(function (t) {
          var b = null; try { b = t ? JSON.parse(t) : null; } catch (e) { b = null; }
          if (!r.ok) { var err = new Error((b && (typeof b.detail === "string" ? b.detail : b.error)) || ("HTTP " + r.status)); err.status = r.status; err.code = b && b.error; throw err; }
          return b;
        });
      });
  }
  function signedIn() { return I().workspace().then(function (w) { return !!w; }); }
  function when(iso) { return iso ? I().stamp(iso) : "not yet"; }
  function sayDay(iso) {
    var d = new Date(iso); if (isNaN(d)) return String(iso || "");
    return d.toLocaleDateString("en-GB", { weekday: "short", day: "numeric", month: "short", timeZone: "UTC" }).replace(",", "");
  }
  function mailto(addr, d, r) {
    var subject = "Post-quantum migration: " + d;
    var body = "Hi SOQLAB team,\n\nWe own " + d + " (claimed in Morrow). Its grade is " + (r && r.grade ? r.grade : "[grade]") +
      (r && r.key_exchange && r.key_exchange.group ? ", key exchange " + r.key_exchange.group : "") +
      ". We'd like to talk about migrating [which systems] to post-quantum cryptography.\n\nThanks,";
    return "mailto:" + addr + "?subject=" + encodeURIComponent(subject) + "&body=" + encodeURIComponent(body);
  }

  /* ── the domain page ───────────────────────────────────────────────────── */
  var D = { d: null, r: null, tp: null, pub: null, mine: null, watch: null, signed: null, busy: false, msg: "", tone: null, record: null };

  function domain(d, r) {
    var fresh = D.d !== d;
    D.r = r;
    if (fresh) { D = { d: d, r: r, tp: null, pub: null, mine: null, watch: null, signed: null, busy: false, msg: "", tone: null, record: null }; load(); }
    else paint();
  }
  function services(d, tp) { if (D.d === d) { D.tp = tp; paint(); } }

  function load() {
    var d = D.d;
    var pub = I().getJSON("/api/public/claim/" + I().enc(d), { cache: "no-store" }).catch(function () { return null; });
    Promise.all([pub, signedIn()]).then(function (x) {
      if (D.d !== d) return;
      D.pub = x[0]; D.signed = x[1];
      if (!D.signed) { paint(); return; }
      return Promise.all([
        send("GET", "/instrument/watch/" + I().enc(d)).catch(function () { return null; }),
        send("GET", "/instrument/claims/" + I().enc(d)).catch(function () { return null; })
      ]).then(function (y) { if (D.d !== d) return; D.watch = y[0]; D.mine = y[1]; paint(); });
    });
  }

  function act(p, okMsg) {
    D.busy = true; D.msg = ""; paint();
    return p.then(function (res) { D.busy = false; D.msg = okMsg || ""; D.tone = "ok"; return res; })
      .catch(function (e) { D.busy = false; D.msg = e.message; D.tone = "bad"; paint(); throw e; });
  }

  function fixPlan() {
    var r = D.r || {}, steps = [];
    (r.fixes || []).slice(0, 1).forEach(function (f) { steps.push(f.title + (f.requires ? " (needs " + f.requires + ")" : "") + "."); });
    var exposed = ((D.tp && D.tp.services) || []).filter(function (s) { return s.status === "classical" || s.status === "no_tls"; });
    exposed.slice(0, 6).forEach(function (s) { steps.push(s.fix || ("Ask " + (s.vendor || s.host) + " when " + s.host + " will offer a post-quantum key exchange.")); });
    if (!steps.length) steps.push("Nothing to change on " + D.d + " itself. Keep watching: Morrow tells you if that changes.");
    steps.push("Re-check after each change. Morrow keeps watching " + D.d + " and tells you the day it lands.");
    return steps;
  }

  function paint() {
    var box = document.getElementById("w-wrap"); if (!box || !D.d) return;
    var X = I(), d = D.d, esc = X.esc, depth = X.depth();
    var pub = D.pub || {}, mine = D.mine || {}, w = D.watch || {};
    var lines = [], body = "";
    var claimLine = pub.claimed
      ? '<p class="i-fine">' + esc(d) + " has been claimed by its owner since " + esc(X.day(pub.since)) + "." + (pub.reply ? "</p><p><b>The owner says</b> (" + esc(X.day(pub.reply.at)) + "): " + esc(pub.reply.text) : "") + "</p>"
      : '<p class="i-fine" id="w-claim-line">Is this your domain? <a href="#w-claim" id="w-claim-go">Claim it</a> to get alerts when this changes.</p>';
    if (D.signed === null) { box.innerHTML = X.panel("", "Watch", '<p class="i-status">Reading whether you watch ' + esc(d) + "&hellip;</p>", { ch: "trust", id: "w-panel" }); return; }
    if (!D.signed) {
      body = '<p id="w-say">' + esc(X.byDepth({
        plain: "Want to know when " + d + " changes? Sign in and watch it.",
        standard: "Get told when " + d + " changes: sign in and watch it. Morrow re-checks it every day and tells you by browser notification, webhook or a private feed. No email.",
        expert: "Watch " + d + ": scheduled re-checks (same guarded probes), change detection on key exchange, grade, certificate and outside services; delivery by Web Push (VAPID), webhook or a private Atom feed."
      })) + '</p><div class="i-row"><a class="i-btn solid" id="w-signin" href="/ui/">Sign in to watch</a><a class="i-btn" href="/about-scanner">What Morrow checks</a></div>' + claimLine;
      box.innerHTML = X.panel("", "Watch", body, { ch: "trust", id: "w-panel" });
      bindClaimLine(false);
      return;
    }
    if (w.watching) {
      var st = w.state || {};
      lines.push("You're watching " + d + ". " + (st.checked_at ? "Last checked " + when(st.checked_at) + "; next around " + when(w.next_check) + "." : "Its first scheduled check is due now."));
    } else lines.push(X.byDepth({ plain: "Watch " + d + " to hear when it changes.", standard: "Watch " + d + ": Morrow re-checks it every " + (w.interval_hours || 24) + " hours and tells you the day its answer changes.", expert: "Watch " + d + ": re-checked every " + (w.interval_hours || 24) + " h; you get a change event when the key exchange, grade, certificate or an outside service changes." }));
    body += '<p id="w-say">' + esc(lines.join(" ")) + "</p>";
    var ev = w.events || [];
    if (ev.length) body += '<div class="i-table-wrap"><table class="i-table" id="w-events"><tbody>' + ev.slice(0, 5).map(function (e) { return '<tr><td class="mono">' + esc(sayDay(e.at)) + "</td><td>" + esc(e.sentence) + "</td></tr>"; }).join("") + "</tbody></table></div>";
    body += '<div class="i-row">' + (w.watching
      ? '<button type="button" class="i-btn" id="w-stop">Stop watching</button><a class="i-btn" href="/watching">Where alerts go</a>'
      : '<button type="button" class="i-btn solid" id="w-start">Watch this domain</button>') + "</div>";
    if (mine.claimed) {
      var steps = fixPlan();
      body += '<h3 id="w-owner">You own ' + esc(d) + "</h3>" +
        "<p>Your fix plan:</p><ol id=\"w-plan\">" + steps.map(function (s) { return "<li>" + esc(s) + "</li>"; }).join("") + "</ol>" +
        '<div class="i-row"><a class="i-btn solid" id="w-contact" href="' + esc(mailto(mine.contact || "contact@soqlab.com", d, D.r)) + '">Talk to SOQLAB about migrating</a>' +
        '<span class="i-fine">Opens your own mail app with a draft to ' + esc(mine.contact || "contact@soqlab.com") + ". Nothing is sent until you press send.</span></div>" +
        '<p><label for="w-reply">Your public reply on ' + esc(d) + "'s page (280 characters)</label></p>" +
        '<div class="i-field"><input id="w-reply" type="text" maxlength="280" autocomplete="off" value="' + esc(pub.reply ? pub.reply.text : "") + '" placeholder="We are rolling out X25519MLKEM768 in Q1."></div>' +
        '<div class="i-row"><button type="button" class="i-btn" id="w-reply-save">Publish reply</button>' + (pub.reply ? '<button type="button" class="i-btn" id="w-reply-del">Remove reply</button>' : "") + "</div>" +
        '<p class="i-fine">Claimed ' + esc(X.day(mine.claimed_at)) + ' by DNS.</p><div class="i-row"><button type="button" class="i-btn" id="w-release">Give up the claim</button><button type="button" class="i-btn" id="w-optout">Stop Morrow checking ' + esc(d) + "</button></div>";
    } else if (mine.claimed_by_other) {
      body += '<p class="i-fine">Another organization has claimed ' + esc(d) + ". If you control its DNS, you can still claim it: the claim moves once their record is gone.</p>" + claimPart(mine);
    } else {
      body += claimLine + claimPart(mine);
    }
    if (D.msg) body += '<p class="i-status" id="w-msg" data-tone="' + esc(D.tone || "") + '" role="status">' + esc(D.msg) + "</p>";
    box.innerHTML = X.panel("", "Watch", body, { ch: "trust", id: "w-panel" });
    if (D.busy) X.$$("#w-panel button").forEach(function (b) { b.setAttribute("aria-busy", "true"); });
    bindDomain();
  }

  function claimPart(mine) {
    var X = I(), esc = X.esc, rec = mine && mine.record;
    if (!D.record && !rec) return '<div id="w-claim"></div>';
    rec = D.record || rec;
    return '<div id="w-claim"><p>' + esc(X.byDepth({
      plain: "Add this record at your DNS provider, then press Check.",
      standard: "Publish this DNS record for " + D.d + ", then press Check. It proves you control the domain; no email, no call.",
      expert: "Publish the TXT record below (exact domain, not a parent). Morrow reads it live; one organization holds a claim while its record stays published."
    })) + '</p><dl class="readouts">' + X.reading("Name", '<code id="w-rec-name">' + esc(rec.name) + "</code>") + X.reading("Type", "TXT") +
      X.reading("Value", '<code id="w-rec-value">' + esc(rec.value) + "</code>") + '</dl><div class="i-row"><button type="button" class="i-btn" data-wcopy="w-rec-name">Copy name</button>' +
      '<button type="button" class="i-btn" data-wcopy="w-rec-value">Copy value</button><button type="button" class="i-btn solid" id="w-check">Check DNS now</button></div>' +
      (mine && mine.last_error ? '<p class="i-fine">' + esc(mine.last_error) + "</p>" : "") + "</div>";
  }

  function bindClaimLine(signed) {
    var a = document.getElementById("w-claim-go"); if (!a) return;
    a.addEventListener("click", function (e) {
      e.preventDefault();
      if (!signed) { location.href = "/ui/"; return; }
      act(send("POST", "/instrument/claims/" + I().enc(D.d)), "Publish the record below, then press Check DNS now.")
        .then(function (res) { D.mine = res; D.record = res.record; paint(); }, function () {});
    });
  }

  function bindDomain() {
    var X = I(), d = D.d, e = X.enc(d);
    bindClaimLine(true);
    var on = function (id, fn) { var el = document.getElementById(id); if (el) el.addEventListener("click", fn); };
    on("w-start", function () { act(send("PUT", "/instrument/watch/" + e), "Watching " + d + ".").then(function (res) { D.watch = res; paint(); }, function () {}); });
    on("w-stop", function () { act(send("DELETE", "/instrument/watch/" + e), "Stopped watching " + d + ".").then(function () { return send("GET", "/instrument/watch/" + e); }).then(function (res) { D.watch = res; paint(); }, function () {}); });
    on("w-check", function () {
      act(send("POST", "/instrument/claims/" + e + "/check"), "Claimed. " + d + " is yours in Morrow, and you're watching it.")
        .then(function (res) { D.mine = res; D.record = null; return Promise.all([send("GET", "/instrument/watch/" + e), X.getJSON("/api/public/claim/" + e, { cache: "no-store" })]); })
        .then(function (y) { D.watch = y[0]; D.pub = y[1]; paint(); X.flash(document.getElementById("w-owner")); }, function () {});
    });
    on("w-reply-save", function () {
      var text = (document.getElementById("w-reply") || {}).value || "";
      act(send("PUT", "/instrument/replies/" + e, { text: text }), "Your reply is on the page.").then(function () { return X.getJSON("/api/public/claim/" + e, { cache: "no-store" }); }).then(function (p) { D.pub = p; paint(); }, function () {});
    });
    on("w-reply-del", function () { act(send("DELETE", "/instrument/replies/" + e), "Reply removed.").then(function () { return X.getJSON("/api/public/claim/" + e, { cache: "no-store" }); }).then(function (p) { D.pub = p; paint(); }, function () {}); });
    on("w-release", function () { act(send("DELETE", "/instrument/claims/" + e), "You gave up the claim on " + d + ".").then(function () { return send("GET", "/instrument/claims/" + e); }).then(function (m) { D.mine = m; return X.getJSON("/api/public/claim/" + e, { cache: "no-store" }); }).then(function (p) { D.pub = p; paint(); }, function () {}); });
    on("w-optout", function () {
      if (!window.confirm("Morrow will never connect to " + d + " or any name under it again, and its stored result is deleted. Watching stops working for it. Go ahead?")) return;
      act(send("POST", "/instrument/claims/" + e + "/opt-out"), d + " is opted out: Morrow will not connect to it again.").then(function () { paint(); }, function () {});
    });
    X.$$("[data-wcopy]").forEach(function (b) { b.addEventListener("click", function () { X.copy(document.getElementById(b.getAttribute("data-wcopy")).textContent, b); }); });
  }

  /* ── browser push ──────────────────────────────────────────────────────── */
  function pushSupported() { return "serviceWorker" in navigator && "PushManager" in window && "Notification" in window; }
  function keyBytes(b64) {
    var s = String(b64).replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "=";
    var raw = atob(s), out = new Uint8Array(raw.length); for (var i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i); return out;
  }
  function activeReg(reg) {
    return new Promise(function (res) {
      var w = reg.installing || reg.waiting;
      if (reg.active && !w) { res(reg); return; }
      w.addEventListener("statechange", function (ev) { if (ev.target.state === "activated") res(reg); });
    });
  }
  function currentSub() {
    if (!pushSupported()) return Promise.resolve(null);
    return navigator.serviceWorker.getRegistration("/ui/").then(function (reg) { return reg ? reg.pushManager.getSubscription() : null; }).catch(function () { return null; });
  }
  function pushOn(publicKey) {
    return Notification.requestPermission().then(function (p) {
      if (p !== "granted") throw new Error("This browser did not allow notifications. Allow them for this site in the browser's settings, then try again.");
      return navigator.serviceWorker.register("/ui/watch-sw.js", { scope: "/ui/" });
    }).then(activeReg).then(function (reg) {
      return reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: keyBytes(publicKey) });
    }).then(function (sub) { var j = sub.toJSON(); return send("POST", "/instrument/watch-push", { endpoint: j.endpoint, keys: j.keys || {} }); });
  }
  function pushOff() {
    return currentSub().then(function (sub) {
      if (!sub) return null;
      var ep = sub.endpoint;
      return sub.unsubscribe().then(function () { return send("DELETE", "/instrument/watch-push", { endpoint: ep }); });
    });
  }

  /* ── /watching ─────────────────────────────────────────────────────────── */
  function watching() {
    var X = I(), esc = X.esc, main = X.main;
    X.setView("trust", "Watching");
    X.say("Reading the domains you watch…");
    main.innerHTML = '<div id="wv"></div>';
    var S = { o: null, sub: null, feedUrl: "", msg: "", tone: null, test: null };
    signedIn().then(function (yes) {
      if (!yes) {
        X.say("Sign in to see the domains you watch and what changed on them.");
        main.innerHTML = X.panel("", "Watching", '<p>Watching needs an account: open any domain\'s page, for example <a href="/example.com">/example.com</a>, and press Watch. Morrow re-checks it and tells you by browser notification, webhook or a private feed. No email.</p><div class="i-row"><a class="i-btn solid" href="/ui/">Sign in</a><a class="i-btn" href="/trial">Make an account</a></div>', { ch: "trust" });
        return;
      }
      reload();
    });
    function reload() {
      return Promise.all([send("GET", "/instrument/watch"), currentSub()]).then(function (x) { S.o = x[0]; S.sub = x[1]; paintW(); })
        .catch(function (e) { X.say("Morrow could not read the domains you watch: " + e.message); });
    }
    function act2(p, ok) { return p.then(function (r) { S.msg = ok; S.tone = "ok"; return r; }, function (e) { S.msg = e.message; S.tone = "bad"; paintW(); throw e; }); }
    function paintW() {
      var o = S.o, ws = o.watches || [], ev = o.events || [], push = o.push || {}, set = o.settings || {};
      var n = ws.length;
      X.say(!n ? "You don't watch any domain yet. Open a domain's page and press Watch."
        : ev.length ? X.byDepth({ plain: ev[0].sentence, standard: ev[0].sentence + " (" + n + " domain" + (n === 1 ? "" : "s") + " watched.)", expert: ev[0].sentence + " " + n + " watched; " + ev.length + " change events stored; re-check every " + set.interval_hours + " h." })
        : "Nothing has changed on the " + (n === 1 ? "domain" : n + " domains") + " you watch since you started. Morrow re-checks every " + (set.interval_hours || 24) + " hours.");
      var changes = !ev.length ? '<p class="i-empty">No changes yet. When a domain becomes post-quantum ready, regresses, changes certificate in a way that moves its grade, or an outside service it depends on changes, it is listed here first.</p>'
        : '<div class="i-table-wrap"><table class="i-table" id="wv-events"><thead><tr><th>When</th><th>What changed</th></tr></thead><tbody>' + ev.map(function (e) { return '<tr><td class="mono">' + esc(sayDay(e.at)) + '</td><td><a href="/' + X.enc(e.domain) + '">' + esc(e.sentence) + "</a></td></tr>"; }).join("") + "</tbody></table></div>";
      var list = !n ? '<p class="i-empty">Nothing watched.</p>' : '<div class="i-table-wrap"><table class="i-table" id="wv-list"><thead><tr><th>Domain</th><th>Grade</th><th>Key exchange</th><th>Last checked</th>' + (X.depth() === "plain" ? "" : "<th>Next</th>") + "<th></th></tr></thead><tbody>" +
        ws.map(function (w) { var st = w.state || {}; return '<tr><td><a href="/' + X.enc(w.domain) + '">' + esc(w.domain) + "</a>" + (w.source === "claim" ? ' <span class="i-fine">yours</span>' : "") + "</td><td>" + (st.grade ? '<span class="g-chip" data-g="' + esc(st.grade) + '">' + esc(st.grade) + "</span>" : "-") + '</td><td class="mono">' + esc(st.key_exchange || "-") + '</td><td class="mono">' + esc(st.checked_at ? X.day(st.checked_at) : "due") + (st.last_error ? ' <span class="v-warn" title="' + esc(st.last_error) + '">failed</span>' : "") + "</td>" + (X.depth() === "plain" ? "" : '<td class="mono">' + esc(w.next_check ? X.day(w.next_check) : "now") + "</td>") + '<td><button type="button" class="i-btn" data-unwatch="' + esc(w.domain) + '">Stop</button></td></tr>'; }).join("") + "</tbody></table></div>";
      var pushHtml = !push.enabled ? '<p id="wv-push" class="i-fine">' + esc(push.reason) + "</p>"
        : !pushSupported() ? '<p id="wv-push" class="i-fine">This browser cannot receive push notifications.</p>'
        : '<p id="wv-push">' + (S.sub ? "This browser gets a notification for every change." : "This browser gets nothing yet.") + (push.subscriptions ? " " + push.subscriptions + " browser" + (push.subscriptions === 1 ? "" : "s") + " turned on in total." : "") + '</p><div class="i-row"><button type="button" class="i-btn' + (S.sub ? "" : " solid") + '" id="wv-push-btn">' + (S.sub ? "Turn off in this browser" : "Turn on in this browser") + "</button></div>";
      var chans = o.channels || [];
      var hookHtml = (chans.length ? '<ul id="wv-hooks">' + chans.map(function (c) { return "<li><span class=\"mono\">" + esc(c.kind === "slack_webhook" ? "Slack" : "Webhook") + "</span> " + esc(c.target_hint) + (c.last_status ? ' <span class="i-fine">last: ' + esc(c.last_status) + "</span>" : "") + ' <button type="button" class="i-btn" data-unhook="' + esc(c.id) + '">Remove</button></li>'; }).join("") + "</ul>" : '<p class="i-fine">No webhook yet.</p>') +
        '<div class="i-row"><select id="wv-kind" class="i-btn" aria-label="Kind"><option value="slack_webhook">Slack</option><option value="generic_webhook">Generic webhook (JSON)</option></select></div>' +
        '<div class="i-field"><span class="p" aria-hidden="true">&rsaquo;</span><input id="wv-url" type="url" autocomplete="off" spellcheck="false" placeholder="https://hooks.slack.com/services/…" aria-label="Webhook URL"></div><div class="i-row"><button type="button" class="i-btn" id="wv-add">Add webhook</button></div>' +
        (X.depth() === "expert" ? '<p class="i-fine">A generic webhook receives JSON:</p><pre>' + esc(JSON.stringify({ source: "morrow", type: "watch.change", domain: "statements.example.com", link: location.origin + "/statements.example.com", changes: [{ kind: "pq_ready", sentence: "statements.example.com became post-quantum ready on Tue 14 Nov — the handshake now uses X25519MLKEM768.", at: "2026-11-14T06:00:00Z" }] }, null, 2)) + "</pre>" : "");
      var feedHtml = S.feedUrl ? '<p>Your private feed. Copy it now: Morrow keeps only a hash of it, so this is the only time it is shown.</p><pre id="wv-feed-url">' + esc(S.feedUrl) + '</pre><div class="i-row"><button type="button" class="i-btn" id="wv-feed-copy">Copy</button></div>'
        : "<p>" + (o.feed && o.feed.exists ? "You have a private feed address, made " + esc(X.day(o.feed.created_at)) + ". Anyone with it can read what changed on your domains; a new address ends this one." : "A private Atom feed of these changes, for a feed reader or your own tooling.") + "</p>";
      feedHtml += '<div class="i-row"><button type="button" class="i-btn" id="wv-feed-new">' + (o.feed && o.feed.exists ? "Make a new address" : "Make a feed address") + "</button>" + (o.feed && o.feed.exists ? '<button type="button" class="i-btn" id="wv-feed-drop">Stop the feed</button>' : "") + "</div>";
      var testHtml = '<div class="i-row"><button type="button" class="i-btn" id="wv-test">Send a test to every channel</button></div>' + (S.test ? '<p class="i-fine" id="wv-test-out">' + esc(testSummary(S.test)) + "</p>" : "");
      var msg = S.msg ? '<p class="i-status" id="wv-msg" role="status" data-tone="' + esc(S.tone || "") + '">' + esc(S.msg) + "</p>" : "";
      main.innerHTML = msg + X.panel("", "What changed", changes, { ch: "trust" }) +
        '<div class="ch-grid"><div class="span-6">' + X.panel("", "What you watch", list, { ch: "grade" }) + "</div>" +
        '<div class="span-6">' + X.panel("", "Where alerts go", "<h3>This browser</h3>" + pushHtml + "<h3>Webhooks</h3>" + hookHtml + "<h3>Private feed</h3>" + feedHtml + testHtml +
          '<p class="i-fine">Never email. How often Morrow connects, and what it sends: <a href="/about-scanner">about the scanner</a>.</p>', { ch: "tools" }) + "</div></div>";
      bindW();
    }
    function testSummary(t) {
      var parts = [];
      (t.push || []).forEach(function (p) { parts.push("browser: " + (p.ok ? "delivered" : p.error)); });
      (t.webhooks || []).forEach(function (h) { parts.push(h.hint + ": " + (h.ok ? "delivered" : h.error)); });
      return parts.length ? parts.join("; ") + "." : "No channel to test yet. Turn on this browser or add a webhook.";
    }
    function bindW() {
      var on = function (id, fn) { var el = document.getElementById(id); if (el) el.addEventListener("click", fn); };
      X.$$("[data-unwatch]").forEach(function (b) { b.addEventListener("click", function () { var d = b.getAttribute("data-unwatch"); act2(send("DELETE", "/instrument/watch/" + X.enc(d)), "Stopped watching " + d + ".").then(reload, function () {}); }); });
      X.$$("[data-unhook]").forEach(function (b) { b.addEventListener("click", function () { act2(send("DELETE", "/instrument/watch-channels/" + X.enc(b.getAttribute("data-unhook"))), "Webhook removed.").then(reload, function () {}); }); });
      on("wv-push-btn", function (e) { e.target.setAttribute("aria-busy", "true"); act2(S.sub ? pushOff() : pushOn(S.o.push.public_key), S.sub ? "This browser will get no more notifications." : "This browser will get a notification for every change.").then(reload, function () {}); });
      on("wv-add", function () { act2(send("POST", "/instrument/watch-channels", { kind: document.getElementById("wv-kind").value, target: document.getElementById("wv-url").value }), "Webhook added. Send a test to check it.").then(reload, function () {}); });
      on("wv-feed-new", function () { act2(send("POST", "/instrument/watch-feed"), "New feed address made.").then(function (r) { S.feedUrl = r.url; return reload(); }, function () {}); });
      on("wv-feed-drop", function () { act2(send("DELETE", "/instrument/watch-feed"), "The feed address no longer works.").then(function () { S.feedUrl = ""; return reload(); }, function () {}); });
      on("wv-feed-copy", function (e) { X.copy(S.feedUrl, e.target); });
      on("wv-test", function (e) { e.target.setAttribute("aria-busy", "true"); act2(send("POST", "/instrument/watch-test"), "Test sent.").then(function (t) { S.test = t; paintW(); }, function () {}); });
    }
  }

  /* ── /about-scanner ────────────────────────────────────────────────────── */
  function aboutScanner() {
    var X = I(), esc = X.esc, main = X.main;
    X.setView("trust", "About the scanner");
    var host = (new URL(location.href).searchParams.get("host") || "").toLowerCase();
    X.say(X.byDepth({
      plain: "You found MorrowPQCheck in your logs. It is Morrow checking how well a website's traffic is protected from future quantum computers, and it always says who it is.",
      standard: "You found MorrowPQCheck in your logs: Morrow's post-quantum readiness check. It reads your TLS handshake and your homepage's headers, names itself in every request, and links to your own result.",
      expert: "MorrowPQCheck/1.0: TLS handshakes to :443 with post-quantum groups offered, one HEAD / and, for the outside-service check, one GET / of the homepage. SSRF-guarded, pinned address, opt-out honoured before DNS."
    }));
    main.innerHTML = '<label class="sr-only" for="as-q">Your domain</label><div class="i-field"><span class="p" aria-hidden="true">&rsaquo;</span><input id="as-q" type="text" autocomplete="off" spellcheck="false" inputmode="url" placeholder="your-domain.com" value="' + esc(host) + '"></div>' +
      '<p class="i-fine" id="as-hint">Type your domain to open your own result.</p><div id="as-body"><p class="i-status">Reading what this server sends&hellip;</p></div>';
    var q = document.getElementById("as-q");
    q.addEventListener("keydown", function (e) { if (e.key === "Enter") { var v = String(q.value || "").trim().toLowerCase().replace(/^[a-z]+:\/\//, "").split(/[/?#]/)[0]; if (v) location.href = "/" + encodeURIComponent(v); } });
    X.getJSON("/api/public/scanner" + (host ? "?host=" + X.enc(host) : ""), { cache: "no-store" }).then(function (f) {
      var expert = X.depth() === "expert", plain = X.depth() === "plain";
      var ident = '<dl class="readouts">' + X.reading("User-Agent", '<code id="as-ua">' + esc(f.user_agent) + "</code>") +
        X.reading(f.header.name, "<code>" + esc(f.header.example) + "</code>") + X.reading("From header", "none: nobody is written to") + "</dl>";
      var what = "<ul>" + f.what.map(function (w) { return "<li><b>" + esc(w.part) + ".</b> " + esc(w.sends) + "</li>"; }).join("") + "</ul>";
      var oft = '<div class="i-table-wrap"><table class="i-table" id="as-when"><thead><tr><th>Why</th><th>How often</th></tr></thead><tbody>' + f.when.map(function (w) { return "<tr><td>" + esc(w.why) + "</td><td>" + esc(w.how_often) + "</td></tr>"; }).join("") + "</tbody></table></div>";
      var never = "<ul>" + f.never.map(function (x) { return "<li>" + esc(x) + "</li>"; }).join("") + "</ul>";
      var stop = "<p>" + esc(f.opt_out.how) + '</p><div class="i-row"><a class="i-btn solid" id="as-optout" href="/abuse">Opt a domain out</a><a class="i-btn" href="' + esc(host ? "/" + host : "/example.com") + '">' + (host ? "See " + esc(host) + "'s result" : "See an example result") + "</a></div>" +
        (f.opt_out.contact ? '<p class="i-fine">Or write to ' + esc(f.opt_out.contact) + ".</p>" : "");
      document.getElementById("as-body").innerHTML =
        '<div class="ch-grid"><div class="span-12">' + X.panel("", "How it names itself", ident, { ch: "trust" }) + "</div>" +
        '<div class="span-6">' + X.panel("", "Make it stop", stop, { ch: "tools" }) + "</div>" +
        '<div class="span-6">' + X.panel("", "What it sends", what + (plain ? "" : '<p class="i-fine">' + esc(f.stored) + "</p>"), { ch: "conn" }) + "</div>" +
        '<div class="span-6">' + X.panel("", "How often", oft, { ch: "league" }) + "</div>" +
        (plain ? "" : '<div class="span-6">' + X.panel("", "Never", never + (expert ? '<p class="i-fine">The guard is services/public_grade.resolve_pinned; the code is <a href="https://github.com/soqlab/Morrow" rel="noopener">public</a>, and <a href="/trust">/trust</a> shows which commit runs here.</p>' : ""), { ch: "ref" }) + "</div>") + "</div>";
    }).catch(function (e) { document.getElementById("as-body").innerHTML = '<p class="i-status" data-tone="bad">' + esc(e.message) + "</p>"; });
  }

  window.MorrowWatch = { domain: domain, services: services, watching: watching, aboutScanner: aboutScanner };
})();
