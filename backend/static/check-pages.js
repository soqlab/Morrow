/* ============================================================================
   The free checker's companion pages: /public-check/terms,
   /public-check/acceptable-use, /abuse, /public-check/privacy and /scanner.

   One job: put this deployment's real values on the page instead of a copy of
   the documented defaults, read from the same source /check reads —
   GET /api/public-check/config.

     [data-abuse-contact]   the published abuse / opt-out address
     [data-config="..."]    one guardrail value

   Every slot ships with honest default markup, so the page is correct with
   JavaScript off and correct on a deployment that has configured nothing: a
   missing abuse address leaves the sentence that says no address is configured,
   rather than inventing one. A value is only ever replaced when the server
   actually returned it.

   No third-party requests. No inline handlers, so these pages live under the
   strict Content-Security-Policy.
   ========================================================================== */
(function () {
  "use strict";

  var contacts = document.querySelectorAll("[data-abuse-contact]");
  var values = document.querySelectorAll("[data-config]");
  if (!contacts.length && !values.length) { return; }

  //: Each reader returns a string, or "" to keep the markup's own default.
  var READERS = {
    log_retention_days: function (g) {
      return g.log_retention_days ? String(g.log_retention_days) : "";
    },
    cache_minutes: function (g) {
      return g.cache_seconds ? String(Math.round(g.cache_seconds / 60)) : "";
    },
    checks_per_domain_per_hour: function (g) {
      return g.checks_per_domain_per_hour ? String(g.checks_per_domain_per_hour) : "";
    }
  };

  function setText(node, text) {
    while (node.firstChild) { node.removeChild(node.firstChild); }
    node.appendChild(document.createTextNode(text));
  }

  function fillContacts(address) {
    Array.prototype.forEach.call(contacts, function (slot) {
      while (slot.firstChild) { slot.removeChild(slot.firstChild); }
      var link = document.createElement("a");
      link.className = "mono";
      link.href = "mailto:" + address;
      link.textContent = address;
      slot.appendChild(link);
    });
  }

  function fillValues(guardrails) {
    Array.prototype.forEach.call(values, function (slot) {
      var reader = READERS[slot.getAttribute("data-config")];
      if (!reader) { return; }
      var text;
      try { text = reader(guardrails); } catch (err) { text = ""; }
      if (text) { setText(slot, text); }
    });
  }

  fetch("/api/public-check/config", { headers: { "Accept": "application/json" } })
    .then(function (response) { return response.ok ? response.json() : null; })
    .then(function (config) {
      if (!config) { return; }
      var guardrails = config.guardrails || {};
      var use = config.acceptable_use || {};
      var address = use.abuse_contact || guardrails.abuse_contact || "";
      if (address) { fillContacts(address); }
      fillValues(guardrails);
    })
    .catch(function () { /* the defaults in the markup are already true */ });
}());
