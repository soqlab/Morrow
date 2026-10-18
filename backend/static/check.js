/* ============================================================================
   /check — the free public post-quantum readiness checker.

   Rules this file follows:
     * No third-party requests. Every fetch goes to this origin's own API.
     * No inline handlers and no inline <script>, so the page can live under the
       strict Content-Security-Policy (script-src 'self').
     * A GET never starts a check. Arriving at a permalink reads the cache; if
       the cached result has expired the visitor is offered a button, because
       following a shared link must never turn into a connection to someone
       else's server.
     * Nothing is presented as measured unless the API said it was measured.
       "not observed" is rendered as "not observed", never as "none".
   ========================================================================== */
(function () {
  "use strict";

  var API = "/api/public-check";

  var form = document.getElementById("check-form");
  var input = document.getElementById("check-domain");
  var submit = document.getElementById("check-submit");
  var status = document.getElementById("check-status");
  var result = document.getElementById("check-result");

  var busy = false;

  // ── small helpers ─────────────────────────────────────────────────────────

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) { node.className = className; }
    if (text !== undefined && text !== null) { node.textContent = String(text); }
    return node;
  }

  function clear(node) { while (node && node.firstChild) { node.removeChild(node.firstChild); } }

  function fill(id, text) {
    var node = document.getElementById(id);
    if (node) { node.textContent = text === undefined || text === null ? "" : String(text); }
  }

  function list(id, items) {
    var node = document.getElementById(id);
    if (!node) { return; }
    clear(node);
    (items || []).forEach(function (item) { node.appendChild(el("li", null, item)); });
  }

  function titleCase(value) {
    return String(value || "").replace(/[_-]+/g, " ").replace(/^./, function (c) { return c.toUpperCase(); });
  }

  function domainFromPath() {
    // /check/{domain} now redirects to the permanent record at /r/{domain}, so the record page
    // sends people here with ?domain= instead. The old path form is still read, because a link
    // somebody saved before the redirect existed should still prefill the form.
    var query = /[?&]domain=([^&]+)/.exec(window.location.search || "");
    var match = query || /^\/check\/(.+)$/.exec(window.location.pathname || "");
    if (!match) { return ""; }
    try { return decodeURIComponent(match[1].replace(/\+/g, " ")); } catch (err) { return match[1]; }
  }

  function setStatus(kind, text, extra) {
    status.className = "check-status" + (kind ? " " + kind : "");
    clear(status);
    if (!text) { return; }
    if (kind === "error") {
      var strong = el("strong", null, (extra && extra.heading) || "Refused");
      status.appendChild(strong);
      status.appendChild(document.createTextNode(" — " + text));
    } else {
      status.appendChild(document.createTextNode(text));
    }
  }

  // ── rendering ─────────────────────────────────────────────────────────────

  var CHIP_FOR = {
    quantum_vulnerable: "crit",
    hybrid_key_exchange: "warn",
    post_quantum: "ok",
    inconclusive: "info",
    not_assessed: "warn"
  };

  var CHIP_LABEL = {
    quantum_vulnerable: "Quantum-vulnerable",
    hybrid_key_exchange: "Partly protected",
    post_quantum: "Post-quantum",
    inconclusive: "Inconclusive",
    not_assessed: "Not assessed"
  };

  function renderVerdict(data) {
    var verdict = data.verdict || {};
    var chip = document.getElementById("verdict-chip");
    chip.className = "chip " + (CHIP_FOR[verdict.status] || "info");
    chip.textContent = CHIP_LABEL[verdict.status] || titleCase(verdict.status);
    fill("verdict-headline", verdict.headline || "");
    fill("verdict-explanation", verdict.explanation || "");

    var figures = document.getElementById("verdict-figures");
    clear(figures);
    var observed = data.observed || {};
    var certificate = observed.certificate || {};
    var rows = [
      ["Protocol", observed.tls_version || "not observed"],
      ["Key exchange", observed.key_exchange_observed ? observed.key_exchange : "not observed"],
      ["Certificate key", [certificate.key_type, certificate.key_bits || ""].join(" ").trim() || "not observed"],
      ["Signature", certificate.sig_algorithm || "not observed"],
      ["Expires", certificate.not_after
        ? certificate.not_after + (certificate.days_until_expiry !== null && certificate.days_until_expiry !== undefined
          ? " (" + certificate.days_until_expiry + " days)" : "")
        : "not observed"],
      ["Crypto agility score", verdict.crypto_agility_score === null || verdict.crypto_agility_score === undefined
        ? "not assessed" : verdict.crypto_agility_score + " / 100"]
    ];
    rows.forEach(function (row) {
      var wrap = el("div");
      wrap.appendChild(el("dt", null, row[0]));
      var dd = el("dd");
      var unmeasured = row[1] === "not observed" || row[1] === "not assessed";
      dd.appendChild(unmeasured ? el("span", "unmeasured", row[1]) : document.createTextNode(String(row[1])));
      wrap.appendChild(dd);
      figures.appendChild(wrap);
    });

    var made = observed.connections_made || 1;
    fill("measured-note", observed.reachable
      ? "Measured just now over " + made + (made === 1 ? " connection to " : " connections to ") +
        (observed.address_checked || data.domain) + " on port " + observed.port +
        ". Nothing else was contacted."
      : "Nothing was measured: " + (observed.error || observed.scan_status || "the endpoint did not answer") +
        ". A failed check is reported as failed, not as clean.");
  }

  function renderFacts(data) {
    var body = document.getElementById("facts-body");
    clear(body);
    (data.evidence || []).forEach(function (row) {
      var tr = el("tr");
      tr.appendChild(el("td", null, row.label));
      var value = el("td", "value");
      value.appendChild(document.createTextNode(row.value || "—"));
      if (row.note) { value.appendChild(el("span", "note", row.note)); }
      tr.appendChild(value);
      var source = el("td", "source");
      source.appendChild(el("span", "src " + row.source, titleCase(row.source)));
      tr.appendChild(source);
      body.appendChild(tr);
    });
  }

  var ALGO_CHIP = { compliant: "ok", quantum_vulnerable: "crit", deprecated: "warn", unknown: "info" };

  function renderAlgorithms(data) {
    var wrap = document.getElementById("algorithms");
    clear(wrap);
    var items = data.algorithms || [];
    if (!items.length) {
      wrap.appendChild(el("p", "fine", "No algorithm could be read from this endpoint."));
      return;
    }
    items.forEach(function (item) {
      var card = el("div", "algo-card");
      card.appendChild(el("b", null, item.resolved_as || item.algorithm || ""));
      if (item.role) { card.appendChild(el("span", "algo-role", item.role)); }
      // classify_algorithm returns `details` (why) and `action` (what to do about it).
      if (item.details) { card.appendChild(el("p", null, item.details)); }
      if (item.action && item.action !== "none") {
        card.appendChild(el("p", "algo-action", item.action + "."));
      }
      var chip = el("span", "chip " + (ALGO_CHIP[item.status] || "info"),
        titleCase(item.status) + (item.standards && item.standards.length ? " · " + item.standards.join(", ") : ""));
      card.appendChild(chip);
      if (item.observed_as && item.observed_as !== item.resolved_as) {
        card.appendChild(el("span", "algo-raw", "on the wire: " + item.observed_as));
      }
      wrap.appendChild(card);
    });
  }

  function renderCT(data) {
    var ct = data.certificate_transparency || {};
    var wrap = document.getElementById("ct-block");
    clear(wrap);
    if (ct.status !== "ok") {
      var box = el("div", "ct-unavailable");
      box.appendChild(el("strong", null, ct.status === "skipped"
        ? "Certificate Transparency was not read. "
        : "Certificate Transparency was unavailable. "));
      box.appendChild(document.createTextNode(ct.reason ||
        "No reason was returned. This is not evidence that the domain has no certificates."));
      wrap.appendChild(box);
      return;
    }
    var head = el("p", "ct-head");
    head.appendChild(document.createTextNode(
      (ct.certificate_count === null || ct.certificate_count === undefined ? "Some" : ct.certificate_count) +
      " unexpired certificate(s) logged for this name, read from "));
    if (ct.provider_url) {
      var link = el("a", null, ct.provider);
      link.href = ct.provider_url;
      link.rel = "noopener noreferrer";
      head.appendChild(link);
    } else {
      head.appendChild(document.createTextNode(ct.provider || "the configured provider"));
    }
    head.appendChild(document.createTextNode(". The target was not contacted for any of this."));
    wrap.appendChild(head);

    if ((ct.issuers || []).length) {
      var issuers = el("ul", "tight");
      ct.issuers.slice(0, 5).forEach(function (row) {
        issuers.appendChild(el("li", null, row.issuer + " — " + row.certificates + " certificate(s)"));
      });
      wrap.appendChild(issuers);
    }
    if ((ct.key_history || []).length) {
      var keys = el("ul", "tight");
      ct.key_history.forEach(function (row) {
        keys.appendChild(el("li", null,
          [row.key_type, row.key_bits || ""].join(" ").trim() +
          (row.sig_algorithm ? " signed with " + row.sig_algorithm : "") +
          (row.not_before ? ", issued " + row.not_before : "")));
      });
      wrap.appendChild(el("p", "fine", "Key types in logged certificates, newest first:"));
      wrap.appendChild(keys);
    } else if (ct.reason) {
      wrap.appendChild(el("p", "fine", ct.reason));
    }
  }

  function renderDeadlines(items) {
    var wrap = document.getElementById("deadlines");
    if (!wrap) { return; }
    clear(wrap);
    (items || []).forEach(function (row) {
      var card = el("div", "deadline-card");
      card.appendChild(el("b", null, row.name || row.framework));
      var dates = el("div", "dates");
      [["Plan by", row.soft_deadline], ["Complete by", row.hard_deadline]].forEach(function (pair) {
        if (!pair[1]) { return; }
        var line = el("span");
        line.appendChild(document.createTextNode(pair[0] + " "));
        line.appendChild(el("strong", null, pair[1]));
        dates.appendChild(line);
      });
      card.appendChild(dates);
      card.appendChild(el("p", "who", "Binding on: " + ((row.applies_to || []).join(", ") || "see the authority") +
        ". Authority: " + (row.authority || "—") + "."));
      if (row.reference) {
        var ref = el("a", "fine", "Read the source");
        ref.href = row.reference;
        ref.rel = "noopener noreferrer";
        card.appendChild(ref);
      }
      wrap.appendChild(card);
    });
  }

  function renderHndl(data) {
    var wrap = document.getElementById("hndl-block");
    clear(wrap);
    var hndl = data.harvest_now_decrypt_later || {};
    var verdict = data.verdict || {};
    var first = el("p");
    if (hndl.risk_tier === "unmeasured" || !(data.observed || {}).reachable) {
      first.textContent = "Not modelled. Nothing was observed here, so there is no algorithm to model and " +
        "no number worth showing.";
    } else {
      first.textContent = "If traffic to this endpoint were recorded today and kept, the model puts the " +
        "chance of the key exchange being breakable by " + (hndl.q_day_year_used || "the modelled Q-Day year") +
        " at " + (hndl.break_probability_by_q_day === null || hndl.break_probability_by_q_day === undefined
          ? "an unmodelled level"
          : Math.round(hndl.break_probability_by_q_day * 100) + "%") +
        ", on algorithm class " + (hndl.algorithm_class || "unknown") +
        " (tier: " + (hndl.risk_tier || "unknown") + "; platform risk: " +
        (verdict.harvest_now_decrypt_later_risk || "unknown") + ").";
    }
    wrap.appendChild(first);
    var basis = data.model_basis || {};
    wrap.appendChild(el("p", "hndl-basis", "Modelled, not measured. " + (basis.summary || "") +
      (basis.as_of ? " Model as of " + basis.as_of + "." : "")));
  }

  function renderExports(data) {
    var domain = encodeURIComponent(data.domain || "");
    var permalink = window.location.origin + "/r/" + domain;
    var jsonLink = document.getElementById("export-json");
    var cbomLink = document.getElementById("export-cbom");
    jsonLink.href = API + "/" + domain + "/export.json";
    cbomLink.href = API + "/" + domain + "/cbom.json";

    var copy = document.getElementById("export-permalink");
    copy.href = permalink;
    copy.textContent = "Copy permalink";

    var cache = data.cache || {};
    fill("cache-note", cache.hit
      ? "Served from the cache: checked " + (cache.checked_at || data.checked_at) + ", cached until " +
        (cache.expires_at || "its expiry") + ". A domain is checked once per cache window, not once per visitor."
      : "Checked " + (data.checked_at || "just now") + " and cached for " +
        ((cache.ttl_seconds || 0) / 60).toFixed(0) + " minutes, so the next visitor costs this host nothing.");
  }

  function render(data) {
    fill("result-domain", data.domain || "Result");
    renderVerdict(data);
    renderFacts(data);
    renderAlgorithms(data);
    renderCT(data);
    renderDeadlines(data.deadlines);
    renderHndl(data);
    list("limits-list", data.limits);
    list("adds-list", data.what_a_full_assessment_adds);
    renderExports(data);
    result.hidden = false;
    document.title = data.domain + " — post-quantum readiness check | Morrow";
    if (window.history && window.history.replaceState) {
      // The record URL, not the tool URL: reloading should land on the permanent page, and one
      // record must have exactly one address.
      window.history.replaceState({}, "", "/r/" + encodeURIComponent(data.domain));
    }
  }

  // ── config (the guardrails, read from the server) ─────────────────────────

  var GUARDRAIL_ROWS = [
    ["Port contacted", function (g) { return String(g.port); }],
    ["Connections per check", function () { return "at most 2, to one hostname"; }],
    ["Cache window", function (g) { return Math.round(g.cache_seconds / 60) + " minutes per domain"; }],
    ["Checks per address", function (g) { return g.checks_per_ip_per_minute + " per minute, " + g.checks_per_ip_per_hour + " per hour"; }],
    ["Checks per target domain", function (g) { return g.checks_per_domain_per_hour + " per hour"; }],
    ["Checks for the whole service", function (g) { return g.checks_per_hour_total + " per hour"; }],
    ["Rate-limit store", function (g) { return g.rate_limit_backend; }],
    ["Checks running at once", function (g) { return String(g.concurrent_checks); }],
    ["Queue bound", function (g) { return g.max_queued_checks + " waiting, " + g.queue_wait_seconds + "s maximum wait"; }],
    ["Whole-check deadline", function (g) { return g.deadline_seconds + " seconds"; }],
    ["Certificate Transparency", function (g) {
      var ct = g.certificate_transparency || {};
      return ct.enabled
        ? ct.provider + ", one request every " + ct.min_interval_seconds + "s, " + ct.timeout_seconds + "s timeout"
        : "off on this deployment";
    }],
    ["Domains opted out", function (g) { return String(g.opt_out_domains); }],
    ["Check log retention", function (g) { return g.log_retention_days + " days (addresses salted-hashed)"; }],
    ["Private address targets", function () { return "refused: private, loopback, link-local, CGNAT, reserved, IPv4-mapped"; }]
  ];

  function renderConfig(config) {
    var guardrails = config.guardrails || {};
    var body = document.getElementById("guardrail-body");
    clear(body);
    GUARDRAIL_ROWS.forEach(function (row) {
      var tr = el("tr");
      tr.appendChild(el("td", null, row[0]));
      var value;
      try { value = row[1](guardrails); } catch (err) { value = "—"; }
      tr.appendChild(el("td", "value", value));
      body.appendChild(tr);
    });

    var use = config.acceptable_use || {};
    if (use.summary) { fill("au-summary", use.summary); }
    list("au-does", use.does);
    list("au-does-not", use.does_not);
    list("au-rules", use.rules);
    if (use.abuse_contact) {
      var contact = document.getElementById("abuse-contact");
      clear(contact);
      var link = el("a", "mono", use.abuse_contact);
      link.href = "mailto:" + use.abuse_contact;
      contact.appendChild(link);
    }
    if (!result || result.hidden) {
      renderDeadlines(config.deadlines);
      list("limits-list", config.limits);
      list("adds-list", config.what_a_full_assessment_adds);
    }
    if (guardrails.enabled === false) {
      setStatus("error", "The free checker is switched off on this deployment.", { heading: "Unavailable" });
      if (submit) { submit.disabled = true; }
    }
  }

  // ── requests ──────────────────────────────────────────────────────────────

  function showRefusal(payload, httpStatus) {
    var heading = httpStatus === 429 ? "Rate limited"
      : httpStatus === 503 ? "Busy"
      : httpStatus === 403 ? "Refused"
      : httpStatus >= 500 ? "Check failed"
      : "Not a target we will check";
    setStatus("error", (payload && payload.detail) || "The check could not be run.", { heading: heading });
  }

  function runCheck(domain, refresh) {
    if (busy) { return; }
    busy = true;
    submit.disabled = true;
    result.hidden = true;
    setStatus("working", "Reading Certificate Transparency and completing one handshake with " + domain + "…");
    fetch(API, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify({ domain: domain, refresh: !!refresh })
    }).then(function (response) {
      return response.json().then(function (payload) { return { ok: response.ok, status: response.status, payload: payload }; });
    }).then(function (outcome) {
      if (!outcome.ok) { showRefusal(outcome.payload, outcome.status); return; }
      setStatus("", "");
      render(outcome.payload);
    }).catch(function () {
      setStatus("error", "The request did not complete. Check your connection and try again.", { heading: "No answer" });
    }).then(function () {
      busy = false;
      submit.disabled = false;
    });
  }

  function loadCached(domain) {
    setStatus("working", "Loading the cached result for " + domain + "…");
    fetch(API + "/" + encodeURIComponent(domain), { headers: { "Accept": "application/json" } })
      .then(function (response) {
        return response.json().then(function (payload) { return { ok: response.ok, status: response.status, payload: payload }; });
      })
      .then(function (outcome) {
        if (outcome.ok) {
          setStatus("", "");
          render(outcome.payload);
          return;
        }
        if (outcome.status === 404) {
          // A shared link whose cached result has expired. Offer the check; never run it from a GET.
          setStatus("", "");
          clear(status);
          status.className = "check-status";
          status.appendChild(document.createTextNode(
            "There is no cached result for " + domain + " right now. "));
          var button = el("button", "btn", "Run the check");
          button.type = "button";
          button.addEventListener("click", function () { runCheck(domain, false); });
          status.appendChild(button);
          return;
        }
        showRefusal(outcome.payload, outcome.status);
      })
      .catch(function () {
        setStatus("error", "The cached result could not be loaded.", { heading: "No answer" });
      });
  }

  // ── wiring ────────────────────────────────────────────────────────────────

  form.addEventListener("submit", function (event) {
    event.preventDefault();
    var domain = (input.value || "").trim();
    if (!domain) {
      setStatus("error", "Enter a domain, for example example.com.", { heading: "Nothing to check" });
      input.focus();
      return;
    }
    runCheck(domain, false);
  });

  document.getElementById("recheck").addEventListener("click", function (event) {
    event.preventDefault();
    var domain = (input.value || "").trim() || domainFromPath();
    if (domain) { runCheck(domain, true); }
  });

  document.getElementById("export-permalink").addEventListener("click", function (event) {
    var link = event.currentTarget;
    if (!navigator.clipboard || !navigator.clipboard.writeText) { return; }  // let the link navigate
    event.preventDefault();
    navigator.clipboard.writeText(link.href).then(function () {
      link.textContent = "Permalink copied";
      window.setTimeout(function () { link.textContent = "Copy permalink"; }, 2500);
    }).catch(function () {
      link.textContent = "Copy failed — use the address bar";
    });
  });

  fetch(API + "/config", { headers: { "Accept": "application/json" } })
    .then(function (response) { return response.ok ? response.json() : null; })
    .then(function (config) { if (config) { renderConfig(config); } })
    .catch(function () { /* the page is readable without it; the table keeps its loading row */ });

  var fromPath = domainFromPath();
  if (fromPath) {
    input.value = fromPath;
    loadCached(fromPath);
  }
}());
