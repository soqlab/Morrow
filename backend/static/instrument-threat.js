/*
 * /threat: the quantum threat board (instrument.js calls MorrowThreat.view()).
 *
 * Public evidence of how close a quantum computer that breaks RSA is, read from one reviewed,
 * cited dataset (GET /api/public/threat; services/threat_board.py). The page fetches nothing but
 * that: no live scraping. Charts draw only the dataset's verified entries, each has a table with the
 * same numbers as its text alternative, and every row links its primary source. Same origin only;
 * no inline script or style (colours come from classes in instrument-threat.css).
 */
(function () {
  "use strict";
  function I() { return window.MorrowIns; }
  var NS = "http://www.w3.org/2000/svg";

  var CLAIM = {
    peer_reviewed: "peer-reviewed", preprint: "preprint, not yet peer-reviewed", vendor_claim: "vendor's claim",
    roadmap: "vendor's plan", official: "official", survey: "expert survey"
  };
  var EC = { none: "no error correction", detected: "errors detected, not corrected", corrected: "errors corrected", unclear: "not stated" };

  function num(n) { return n == null ? "-" : Number(n).toLocaleString("en-GB"); }
  function yearOf(s) { return parseInt(String(s || "").slice(0, 4), 10); }
  function frac(s) {  // a date as a fractional year, for the x axis
    var p = String(s || "").split("-"), y = +p[0], m = p[1] ? +p[1] - 1 : 6, d = p[2] ? +p[2] : 15;
    return y + (m + (d - 1) / 31) / 12;
  }
  function when(s) {
    var p = String(s || "").split("-");
    if (p.length === 1) return p[0];
    var months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    return (p[2] ? +p[2] + " " : "") + months[+p[1] - 1] + " " + p[0];
  }
  function src(e) {
    var esc = I().esc;
    return '<a href="' + esc(e.source_url) + '" rel="noopener">' + esc(e.source_title) + "</a>";
  }
  function tag(e) {
    var esc = I().esc;
    return '<span class="tb-tag" data-claim="' + esc(e.claim) + '">' + esc(CLAIM[e.claim] || e.claim) + "</span>" +
      (e.stale ? ' <span class="tb-tag" data-claim="stale">checked over a year ago</span>' : "");
  }

  /* ── a dated scatter on a log scale: one axis, shapes as well as colours ── */
  function el(name, attrs, text) {
    var n = document.createElementNS(NS, name);
    Object.keys(attrs || {}).forEach(function (k) { n.setAttribute(k, attrs[k]); });
    if (text != null) n.textContent = text;
    return n;
  }
  function mark(g, shape, x, y, hollow, cls) {
    var c = "tb-mk " + cls + (hollow ? " tb-hollow" : "");
    if (shape === "square") g.appendChild(el("rect", { x: x - 5, y: y - 5, width: 10, height: 10, rx: 1.5, "class": c }));
    else g.appendChild(el("circle", { cx: x, cy: y, r: 5.5, "class": c }));
  }
  function chart(box, o) {
    var W = 640, H = 280, L = 62, R = 14, T = 14, B = 34;
    var x0 = o.x[0], x1 = o.x[1], e0 = o.y[0], e1 = o.y[1];
    function X(t) { return L + (t - x0) / (x1 - x0) * (W - L - R); }
    function Y(v) { return T + (1 - (Math.log10(v) - e0) / (e1 - e0)) * (H - T - B); }
    var svg = el("svg", { viewBox: "0 0 " + W + " " + H, role: "img", "aria-labelledby": o.id + "-t " + o.id + "-d", "class": "tb-svg" });
    svg.appendChild(el("title", { id: o.id + "-t" }, o.title));
    svg.appendChild(el("desc", { id: o.id + "-d" }, o.desc));
    var axis = el("g", { "class": "tb-axis", "aria-hidden": "true" });
    for (var e = e0; e <= e1; e++) {
      var y = Y(Math.pow(10, e));
      axis.appendChild(el("line", { x1: L, x2: W - R, y1: y, y2: y, "class": "tb-grid" }));
      axis.appendChild(el("text", { x: L - 8, y: y + 4, "text-anchor": "end" }, e >= 9 ? Math.pow(10, e - 9) + "bn" : e >= 6 ? Math.pow(10, e - 6) + "m" : e >= 3 ? Math.pow(10, e - 3) + "k" : String(Math.pow(10, e))));
    }
    for (var t = Math.ceil(x0); t <= x1; t += o.xStep) {
      axis.appendChild(el("line", { x1: X(t), x2: X(t), y1: H - B, y2: H - B + 4, "class": "tb-tick" }));
      axis.appendChild(el("text", { x: X(t), y: H - B + 18, "text-anchor": "middle" }, String(t)));
    }
    axis.appendChild(el("line", { x1: L, x2: W - R, y1: H - B, y2: H - B, "class": "tb-base" }));
    if (o.now) {
      axis.appendChild(el("line", { x1: X(o.now), x2: X(o.now), y1: T, y2: H - B, "class": "tb-now" }));
      axis.appendChild(el("text", { x: X(o.now) - 4, y: T + 10, "text-anchor": "end" }, "now"));
    }
    svg.appendChild(axis);
    o.series.forEach(function (s) {
      s.points.forEach(function (p) {
        var g = el("g", { "class": "tb-pt" });
        g.appendChild(el("title", {}, p.label));
        var px = X(frac(p.t)), py = Y(p.v);
        mark(g, s.shape, px, py, p.hollow, s.cls);
        if (p.bound) g.appendChild(el("path", { d: "M" + (px - 4) + " " + (py + 9) + " l4 6 l4 -6", "class": "tb-bound " + s.cls }));
        svg.appendChild(g);
      });
    });
    box.appendChild(svg);
  }
  function legend(items) {
    var esc = I().esc;
    return '<ul class="tb-legend">' + items.map(function (i) {
      return '<li><svg viewBox="0 0 14 14" width="14" height="14" aria-hidden="true">' +
        (i.shape === "square" ? '<rect x="2" y="2" width="10" height="10" rx="1.5" class="tb-mk ' + i.cls + (i.hollow ? " tb-hollow" : "") + '"/>'
          : i.shape === "bound" ? '<path d="M3 4 l4 6 l4 -6" class="tb-bound ' + i.cls + '"/>'
          : '<circle cx="7" cy="7" r="5" class="tb-mk ' + i.cls + (i.hollow ? " tb-hollow" : "") + '"/>') +
        "</svg>" + esc(i.label) + "</li>";
    }).join("") + "</ul>";
  }
  function table(id, caption, head, rows) {
    var esc = I().esc;
    return '<details class="tb-data"><summary>' + esc(caption) + " (" + rows.length + ")</summary>" +
      '<div class="i-table-wrap"><table class="i-table" id="' + id + '"><caption class="sr-only">' + esc(caption) + "</caption><thead><tr>" +
      head.map(function (h) { return '<th scope="col">' + esc(h) + "</th>"; }).join("") + "</tr></thead><tbody>" +
      rows.map(function (r) { return "<tr>" + r.map(function (c) { return "<td>" + c + "</td>"; }).join("") + "</tr>"; }).join("") +
      "</tbody></table></div></details>";
  }

  /* The ledes are computed from the dataset, so they never say more than its entries do. */
  function best(list, key) { return list.reduce(function (a, e) { return e[key] && (!a || e[key] > a[key]) ? e : a; }, null); }
  function machinesLede(M) {
    var esc = I().esc;
    var p = best(M.filter(function (e) { return e.chart && e.counts !== "atoms_trapped"; }), "physical_qubits");
    var l = best(M.filter(function (e) { return e.chart; }), "logical_qubits");
    var lc = best(M.filter(function (e) { return e.chart && e.error_correction === "corrected"; }), "logical_qubits");
    var out = p ? "The largest working machine here has " + num(p.physical_qubits) + " physical qubits (" + esc(p.org) + ", " + yearOf(p.date_published) + "). " : "";
    if (l) out += "The most logical qubits shown is " + num(l.logical_qubits) + " (" + esc(l.org) + ", " + yearOf(l.date_published) + ", " + esc(EC[l.error_correction] || "") + ")";
    if (lc && lc !== l) out += "; with errors corrected, " + num(lc.logical_qubits) + " (" + esc(lc.org) + ", " + yearOf(lc.date_published) + ")";
    return out + (l ? ". " : "") + "Breaking RSA needs on the order of a thousand logical qubits running for days.";
  }
  function attackLede(list) {
    var esc = I().esc;
    var rsa = list.filter(function (e) { return e.target === "RSA-2048"; });
    if (!rsa.length) return "";
    var first = rsa[0], low = rsa.reduce(function (a, e) { return e.physical_qubits < a.physical_qubits ? e : a; }, rsa[0]);
    function amt(e) { return (e.physical_bound === "fewer than" ? "fewer than " : "about ") + num(e.physical_qubits); }
    return "The physical qubits estimated to break RSA-2048 fell from " + amt(first) + " (" + yearOf(first.date_published) + ") to " + amt(low) +
      " (" + yearOf(low.date_published) + ", " + esc(CLAIM[low.claim] || low.claim) + ").";
  }

  /* ── the view ──────────────────────────────────────────────────────────── */
  function view() {
    var X = I(), esc = X.esc, main = X.main;
    X.setView("ref", "Quantum threat board");
    X.say("Reading the evidence…");
    main.innerHTML = '<div id="tb-body"><p class="i-status">Reading the dataset&hellip;</p></div>';
    X.getJSON("/api/public/threat", { cache: "no-store" }).then(function (b) { paint(b); })
      .catch(function (e) { X.say("The threat board could not be read just now."); document.getElementById("tb-body").innerHTML = '<p class="i-status" data-tone="bad">' + esc(e.message) + "</p>"; });
  }

  function paint(b) {
    var X = I(), esc = X.esc, est = b.estimate, S = b.sections, expert = X.depth() === "expert", plain = X.depth() === "plain";
    var now = new Date(), nowY = now.getUTCFullYear() + now.getUTCMonth() / 12;
    X.say(X.byDepth({
      plain: "How close is a quantum computer that could read today's encrypted traffic? The public evidence, with every source.",
      standard: "The evidence behind Morrow's quantum year: the machines, what an attack would cost, and the deadlines governments have set. Every number links its source.",
      expert: "Edition " + b.version + " of a reviewed dataset (sha256 " + b.sha256.slice(0, 12) + "…). Verified entries only; vendor figures are labelled as claims; nothing here is scraped."
    }));

    var M = S.machines, A = S.attack_cost, D = S.deadlines, V = S.surveys;
    var phys = M.filter(function (e) { return e.chart && e.physical_qubits; });
    var logi = M.filter(function (e) { return e.chart && e.logical_qubits; });
    var aChart = A.filter(function (e) { return e.chart && e.physical_qubits; });

    var head = '<section class="tb-head" aria-labelledby="tb-h1"><h1 id="tb-h1">' + esc(b.headline.sentence) + "</h1>" +
      '<p class="tb-sub">Experts’ estimate for a quantum computer that can break RSA-2048 in a day. Morrow dates recorded traffic from about <b>' + esc(est.low) + "</b>.</p></section>";

    var why = X.panel("", "Why Morrow says about " + est.low, "<p>" + esc(b.headline.why) + "</p>" +
      '<blockquote class="tb-quote" cite="' + esc(est.source_url) + '"><p>“' + esc(est.quote) + '”</p><footer>' +
      '<a href="' + esc(est.source_url) + '" rel="noopener">' + esc(est.source_label) + "</a>, " + esc(when(est.date_published)) + "</footer></blockquote>" +
      '<p class="i-fine">The same years drive the risk sentence, the harvest clock and every public grade. ' + esc(est.high) +
      " is " + esc(est.outer_bound_note.charAt(0).toLowerCase() + est.outer_bound_note.slice(1)) + "</p>", { ch: "ref", id: "why" });

    var machines = X.panel("", "The machines",
      '<p class="tb-lede">' + machinesLede(M) + "</p>" +
      legend([{ shape: "circle", cls: "tb-s1", label: "Physical qubits" }, { shape: "circle", cls: "tb-s1", hollow: true, label: "Atoms held in an array (not a working computer at that size)" },
        { shape: "square", cls: "tb-s2", label: "Logical qubits" }]) +
      '<div class="tb-chart" id="tb-m-chart"></div>' +
      table("tb-m-table", "Every machine milestone, as a table", ["Date", "Who", "What", "Physical", "Logical", "Error correction", "Source"],
        M.map(function (e) {
          return [esc(when(e.date_published)), esc(e.org), esc(e.title) + (e.note && !plain ? '<br><span class="i-fine">' + esc(e.note) + "</span>" : ""),
            num(e.physical_qubits), num(e.logical_qubits), esc(EC[e.error_correction] || "-") + (e.below_threshold ? "; below threshold" : ""),
            src(e) + "<br>" + tag(e) + (expert ? '<br><span class="i-fine">“' + esc(e.quote) + "”</span>" : "")];
        })), { ch: "conn", id: "machines" });

    var attack = X.panel("", "The attack cost",
      '<p class="tb-lede">' + attackLede(aChart) + " Each estimate assumes error rates and speeds no machine has yet reached at that size.</p>" +
      legend([{ shape: "circle", cls: "tb-s1", label: "RSA-2048" }, { shape: "square", cls: "tb-s2", label: "ECC-256" },
        { shape: "circle", cls: "tb-s1", hollow: true, label: "Different kind of qubit (neutral atoms, cat qubits)" }, { shape: "bound", cls: "tb-s1", label: "“fewer than”: an upper bound" }]) +
      '<div class="tb-chart" id="tb-a-chart"></div>' +
      table("tb-a-table", "Every attack-cost estimate, as a table", ["Published", "Target", "Who", "Physical qubits", "Logical qubits", "Time", "Assumes", "Source"],
        A.map(function (e) {
          return [esc(when(e.date_published)), esc(e.target), esc(e.org), e.physical_qubits ? (e.physical_bound === "fewer than" ? "fewer than " : "about ") + num(e.physical_qubits) : "-",
            num(e.logical_qubits), esc(e.runtime || "-"), esc(e.assumptions || "-") + (e.note && !plain ? '<br><span class="i-fine">' + esc(e.note) + "</span>" : ""),
            src(e) + "<br>" + tag(e) + (expert ? '<br><span class="i-fine">“' + esc(e.quote) + "”</span>" : "")];
        })), { ch: "league", id: "attack" });

    var today = now.toISOString().slice(0, 10), years = {};
    D.forEach(function (e) { (years[yearOf(e.deadline)] = years[yearOf(e.deadline)] || []).push(e); });
    var tl = '<ol class="tb-tl">' + Object.keys(years).sort().map(function (y) {
      return '<li class="tb-yr"><span class="tb-y">' + esc(y) + "</span><ul>" + years[y].map(function (e) {
        var past = String(e.deadline) < today.slice(0, String(e.deadline).length);
        return '<li' + (past ? ' class="tb-past"' : "") + "><b>" + esc(e.title) + "</b> <span class=\"i-fine\">" + esc(e.org) + " · " + esc(e.jurisdiction) +
          " · " + esc(when(e.deadline)) + (past ? " · passed" : "") + "</span><br>" + esc(e.what) +
          (plain ? "" : '<br><span class="i-fine">' + src(e) + " (" + esc(e.status) + ", published " + esc(when(e.date_published)) + ")" + (e.note ? ". " + esc(e.note) : "") + "</span>") +
          (expert ? '<br><span class="i-fine">“' + esc(e.quote) + "”</span>" : "") + "</li>";
      }).join("") + "</ul></li>";
    }).join("") + "</ol>";
    var deadlines = X.panel("", "The deadlines", '<p class="tb-lede">Governments are not waiting for the machine: most ask for the switch to be finished by 2035, and the highest-risk systems by about 2030.</p>' + tl, { ch: "trust", id: "deadlines" });

    var surveys = X.panel("", "What experts said, edition by edition",
      '<div class="i-table-wrap"><table class="i-table" id="tb-s-table"><caption class="sr-only">Expert surveys by edition</caption><thead><tr><th scope="col">Survey</th><th scope="col">Experts</th><th scope="col">Within 10 years</th><th scope="col">Within 15 years</th><th scope="col">Source</th></tr></thead><tbody>' +
      V.slice().reverse().map(function (e) {
        function h(y) { var x = (e.horizons || []).filter(function (k) { return k.years === y; })[0]; return !x ? "not stated" : x.high != null ? x.low + "–" + x.high + "%" : "at least " + x.low + "%"; }
        return "<tr><td>" + esc(e.survey_year) + "</td><td>" + esc(e.experts) + "</td><td>" + h(10) + "</td><td>" + h(15) + "</td><td>" + src(e) + " (" + esc(when(e.date_published)) + ")</td></tr>";
      }).join("") + '</tbody></table></div><p class="i-fine">Ranges run from a cautious to a generous reading of the experts’ answers. The question changed slightly between editions; compare with care.</p>', { ch: "atlas", id: "surveys" });

    var unv = b.unverified.length ? "<p>Listed but not used: Morrow could not verify these against their primary source, so they are not charted and do not affect any estimate.</p><ul>" +
      b.unverified.map(function (u) { return '<li><a href="' + esc(u.source_url) + '" rel="noopener">' + esc(u.title) + "</a>. " + esc(u.note) + "</li>"; }).join("") + "</ul>" : "";
    var prov = X.panel("", "Where this comes from", "<p>" + esc(b.policy) + "</p>" + unv +
      '<dl class="readouts">' + X.reading("Edition", esc(b.version) + " (" + esc(when(b.date)) + ")") + X.reading("SHA-256", "<code>" + esc(b.sha256) + "</code>") +
      X.reading("Entries", esc(M.length + A.length + D.length + V.length) + " verified" + (b.stale.length ? ", " + esc(b.stale.length) + " due for a re-check" : "")) + "</dl>" +
      '<p class="i-row"><a class="i-btn" href="' + esc(b.feed) + '">Feed of changes (Atom)</a><a class="i-btn" href="' + esc(b.dataset) + '">The dataset (JSON)</a>' +
      '<a class="i-fine" href="/api/public/threat/schema.json">Schema</a><a class="i-fine" href="https://github.com/soqlab/Morrow/blob/main/' + esc(b.source_file) + '" rel="noopener">Its history in git</a></p>', { ch: "tools", id: "source" });

    document.getElementById("tb-body").innerHTML = head + '<div class="ch-grid"><div class="span-12">' + why + '</div><div class="span-12">' + machines +
      '</div><div class="span-12">' + attack + '</div><div class="span-7">' + deadlines + '</div><div class="span-5">' + surveys + prov + "</div></div>";

    var firstM = Math.floor(Math.min.apply(null, phys.concat(logi).map(function (e) { return frac(e.date_published); })));
    chart(document.getElementById("tb-m-chart"), {
      id: "tb-mc", x: [firstM, Math.ceil(nowY) + 0.2], xStep: 1, y: [0, 4], now: nowY,
      title: "Qubits in published machines, " + firstM + " to now (log scale)",
      desc: "Physical qubits: " + phys.map(function (e) { return e.org + " " + num(e.physical_qubits) + " (" + yearOf(e.date_published) + ")"; }).join("; ") +
        ". Logical qubits: " + logi.map(function (e) { return e.org + " " + num(e.logical_qubits) + " (" + yearOf(e.date_published) + ")"; }).join("; ") + ". The table below lists every value with its source.",
      series: [
        { cls: "tb-s1", shape: "circle", points: phys.map(function (e) { return { t: e.date_published, v: e.physical_qubits, hollow: e.counts === "atoms_trapped", label: when(e.date_published) + ": " + e.org + ", " + num(e.physical_qubits) + (e.counts === "atoms_trapped" ? " atoms held" : " physical qubits") + " (" + (CLAIM[e.claim] || e.claim) + ")" }; }) },
        { cls: "tb-s2", shape: "square", points: logi.map(function (e) { return { t: e.date_published, v: e.logical_qubits, label: when(e.date_published) + ": " + e.org + ", " + num(e.logical_qubits) + " logical qubits, " + (EC[e.error_correction] || "") + " (" + (CLAIM[e.claim] || e.claim) + ")" }; }) }
      ]
    });
    var firstA = Math.floor(Math.min.apply(null, aChart.map(function (e) { return frac(e.date_published); })));
    chart(document.getElementById("tb-a-chart"), {
      id: "tb-ac", x: [firstA, Math.ceil(nowY) + 0.2], xStep: 2, y: [4, 10], now: nowY,
      title: "Physical qubits estimated to break RSA-2048 and ECC-256, by publication date (log scale)",
      desc: aChart.map(function (e) { return e.target + ": " + (e.physical_bound === "fewer than" ? "fewer than " : "about ") + num(e.physical_qubits) + " (" + e.org + ", " + yearOf(e.date_published) + ")"; }).join("; ") + ". The table below lists every estimate, including those that give logical qubits only.",
      series: ["RSA-2048", "ECC-256"].map(function (target, i) {
        return { cls: i ? "tb-s2" : "tb-s1", shape: i ? "square" : "circle", points: aChart.filter(function (e) { return e.target === target; }).map(function (e) {
          return { t: e.date_published, v: e.physical_qubits, hollow: e.qubit_kind === "neutral_atom" || e.qubit_kind === "cat", bound: e.physical_bound === "fewer than",
            label: when(e.date_published) + ": " + e.org + ", " + (e.physical_bound === "fewer than" ? "fewer than " : "about ") + num(e.physical_qubits) + " physical qubits for " + target + (e.runtime ? " in " + e.runtime : "") + " (" + (CLAIM[e.claim] || e.claim) + ")" };
        }) };
      })
    });
    if (location.hash) { var t = document.getElementById(location.hash.slice(1)); if (t) t.scrollIntoView({ block: "start" }); }
  }

  window.MorrowThreat = { view: view };
})();
