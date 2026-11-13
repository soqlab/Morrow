(() => {
  "use strict";
  /* ==========================================================================
     Oops: the page for an address that leads nowhere.

     Plain text: the address that failed, the closest real pages by edit
     distance, and the actions that get the reader somewhere. Nothing moves.

     Used by the console (mounted into #view for an unknown hash route) and by
     the site-wide 404 page (auto-mounts into #oopsRoot).
     ========================================================================== */

  const esc = s => String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/"/g, "&quot;");

  function lev(a, b) {
    a = a.toLowerCase(); b = b.toLowerCase();
    if (!a.length) return b.length;
    if (!b.length) return a.length;
    let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
    for (let i = 1; i <= a.length; i++) {
      const cur = [i];
      for (let j = 1; j <= b.length; j++) cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      prev = cur;
    }
    return prev[b.length];
  }

  /* The closest candidates to what was typed, by edit distance to any word of
     their key; substring matches are favoured. Nothing far away is offered. */
  function closest(query, candidates, n = 3) {
    const q = String(query || "").toLowerCase().replace(/^[#/]+/, "").replace(/\.html?$/, "").replace(/[-_/.]+/g, " ").trim();
    if (!q) return [];
    return candidates.map(c => {
      const key = String(c.key || c.label || "").toLowerCase();
      const words = key.replace(/[-_/.]+/g, " ").split(/\s+/).filter(Boolean);
      let score = Math.min(lev(q, key), ...words.map(w => lev(q, w)), ...q.split(" ").flatMap(part => words.map(w => lev(part, w) + 1)));
      if (words.some(w => w.length > 2 && (q.includes(w) || w.includes(q)))) score -= 2;
      return { ...c, score };
    // Tight on purpose: a suggestion that has nothing to do with what was typed is worse than none.
    }).filter(c => c.score <= Math.min(4, Math.max(2, Math.ceil(q.length * .3))))
      .sort((a, b) => a.score - b.score).slice(0, n);
  }

  function mount(host, { path = location.pathname + location.hash, suggestions = [], actions = [], routes = 0 } = {}) {
    host.innerHTML = `<section class="oops" aria-labelledby="oopsTitle">
      <div class="oopsHead"><span>Error 404</span><span>${routes ? `${esc(routes)} known pages checked` : "no match"}</span></div>
      <div class="oopsBody">
        <h1 id="oopsTitle">Page not found</h1>
        <p>Nothing lives at <code>${esc(path)}</code>. It may have been mistyped or moved.</p>
        ${suggestions.length ? `<nav class="oopsSuggest" aria-label="Closest pages"><span>Closest pages</span>
          ${suggestions.map(s => `<a href="${esc(s.href)}">${esc(s.label)}${s.hint ? `<small>${esc(s.hint)}</small>` : ""}</a>`).join("")}</nav>`
        : `<p class="oopsNone">No page has a name close to that address.</p>`}
        <div class="oopsActions">${actions.map(a => a.href
          ? `<a class="oopsBtn${a.primary ? " pri" : ""}" href="${esc(a.href)}">${esc(a.label)}</a>`
          : `<button class="oopsBtn${a.primary ? " pri" : ""}" type="button" data-oops-action="${esc(a.id)}">${esc(a.label)}</button>`).join("")}</div>
      </div></section>`;
    return host.querySelector(".oops");
  }

  window.airlockOops = { mount, closest };

  // The site-wide 404 page mounts itself.
  const standalone = document.getElementById("oopsRoot");
  if (standalone) {
    const PUBLIC = [
      ["/", "Home", "Morrow"], ["/", "Check a domain", "Free post-quantum check"], ["/security", "Security", "Buyer security FAQ"],
      ["/pricing", "Pricing", "Plans and pilots"], ["/pilot", "Pilot", "Scope an engagement"], ["/support", "Support", "Contact"],
      ["/data-boundary", "Data boundary", "What leaves"], ["/airlock-deployment", "Deployment", "Deployment guide"], ["/dpa", "DPA", "Data processing"],
      ["/privacy", "Privacy", "Privacy policy"], ["/terms", "Terms", "Terms of service"], ["/trust-passport-demo", "Trust Passport", "What a passport contains"],
      ["/enterprise-admin", "Enterprise admin", "How operations run"], ["/ui/", "Console", "Open the workspace"],
    ];
    const candidates = PUBLIC.map(([href, label, hint]) => ({ key: `${href.replace(/\//g, " ")} ${label}`, href, label, hint }));
    mount(standalone, {
      path: location.pathname + location.search,
      suggestions: closest(location.pathname, candidates, 3),
      routes: PUBLIC.length,
      actions: [{ label: "Check a domain", href: "/", primary: true }, { label: "Open console", href: "/ui/" }],
    });
  }
})();
