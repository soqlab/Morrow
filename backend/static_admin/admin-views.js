(() => {
  "use strict";
  /* ==========================================================================
     Operator console pages and hash router.

     Routes look like #/dashboard, #/customers, #/customers/<org_id>. Old
     single-word hashes (#activity, #security, …) are rewritten to their new
     home so bookmarks keep working. Pages built on the original portal panels
     load through AirlockAdmin.loadViewData; the analytics pages below call the
     tracking endpoints and show "not available on this server yet" on a 404
     instead of inventing numbers.
     ========================================================================== */

  const A = window.AirlockAdmin, S = window.AdminShell, C = window.AdminCharts;
  if (!A || !S || !C) return;
  const { $, esc, fmt, asNum, text, empty, emptyRow, skeletonRows, skeletonList, failBox, failRow, fmtTime, statusPill, riskPill, tags, kv } = A;
  const enc = encodeURIComponent;
  const RANGE_KEY = "pqc_admin_range", LAST_ORG_KEY = "pqc_admin_last_org";
  const RANGES = { "24h": "last 24 hours", "7d": "last 7 days", "30d": "last 30 days", "90d": "last 90 days" };
  const NOT_AVAILABLE = "Not available on this server yet.";

  const ROUTES = {
    dashboard: { eyebrow: "Platform operations", title: "Dashboard", desc: "Customer activity, operational health, and the decisions that need your attention." },
    customers: { group: "Customers", title: "Organizations", desc: "Every tenant organization. Filter, sort, export, and open one for its Customer 360." },
    "customer-360": { page: "customer360", group: "Customers", title: "Customer 360", desc: "One organization's activity, members, credentials, flags and lifecycle." },
    users: { group: "Customers", title: "Users", desc: "Tenant users, role assignments, deactivation and session revocation." },
    invitations: { group: "Customers", title: "Invitations", desc: "Create and revoke single-use invitations into an organization." },
    "support-sessions": { group: "Customers", title: "Support sessions", desc: "Read-only view-as-customer sessions: who opened a customer's console, why, for how long, and what they viewed." },
    onboarding: { group: "Customers", title: "Onboarding", desc: "Activation risk across the fleet and each tenant's onboarding checklist." },
    feedback: { group: "Customers", title: "Customer feedback", desc: "Review and triage customer reports across your organizations." },
    trials: { group: "Customers", title: "Trial requests", desc: "People asking for an account. Approving one creates the organization and the invitation; a person decides every request." },
    usage: { group: "Product", title: "Usage & adoption", desc: "Which product capabilities organizations use, and how that is changing." },
    flags: { group: "Product", title: "Feature flags", desc: "The flag catalog and per-organization overrides." },
    announcements: { group: "Product", title: "Announcements", desc: "Tell customers what is happening with a console banner." },
    "api-keys": { group: "Access", title: "API keys", desc: "Issue, rotate, and revoke organization API keys. Secrets are shown once." },
    sessions: { group: "Access", title: "Sessions", desc: "Inspect active sign-in sessions and revoke access for a user or an organization." },
    operators: { group: "Access", title: "Operators & roles", desc: "Named operator credentials, role ceilings, and the identity this console uses." },
    "rate-limits": { group: "Access", title: "Rate limits", desc: "Per-organization rate-limit overrides and recent 429 pressure." },
    health: { group: "Operations", title: "Service health", desc: "Runtime dependencies, alerts, request observability, traffic and log storage." },
    incidents: { group: "Operations", title: "Incidents & abuse", desc: "API errors, latency, rate-limit pressure, and the request window behind them." },
    jobs: { group: "Operations", title: "Background jobs", desc: "Scheduled and queued work with its last run, next run and failures." },
    "alert-routing": { group: "Operations", title: "Alert routing", desc: "Send operator notifications to Slack, email, PagerDuty and webhooks, with a delivery log." },
    maintenance: { group: "Operations", title: "Maintenance mode", desc: "Pause customer writes with a message while you work." },
    autopatch: { group: "Operations", title: "Autopatch", desc: "Governed intake for platform fixes: diagnose, approve, and prepare draft PRs." },
    launch: { group: "Security", title: "Launch readiness", desc: "The machine-checked go-live gate and production readiness checks." },
    "security-truth": { group: "Security", title: "Security truth", desc: "External findings, AI guardrails, and write-path blocks from integrated tools." },
    isolation: { group: "Security", title: "Tenant isolation & RLS", desc: "Prove tenants cannot see each other, and review the row-level security plan." },
    audit: { group: "Security", title: "Audit log", desc: "Tenant audit logs, the administrator audit trail, and authentication history." },
    data: { group: "Security", title: "Data & retention", desc: "Retention runs, state coverage, and customer data exports." },
    notifications: { group: "Operations", title: "Notifications", desc: "Everything the platform raised for operators, most severe first." },
  };
  // Routes some notification sources emit, mapped to the page that shows them.
  const ALIASES = { readiness: "launch", logins: "audit", abuse: "incidents", "go-live": "launch", overview: "dashboard" };
  // The panel on that page a notification is about (see selectRecord); plain #/launch etc. just open the page.
  const ALIAS_FOCUS = { readiness: "gateBody", "go-live": "gateBody", abuse: "abuseBody", logins: "logsBody" };
  const LEGACY = { overview: "dashboard", customers: "customers", access: "users", apikeys: "api-keys", sessions: "sessions", security: "launch", data: "data", incidents: "incidents", feedback: "feedback", autopatch: "autopatch", announcements: "announcements", activity: "audit", traffic: "health", readiness: "launch" };

  let current = { key: "", path: "", org: "", query: new URLSearchParams() };
  let pendingFocus = false;

  // ---------- helpers ----------
  const getRange = () => { try { const r = sessionStorage.getItem(RANGE_KEY); return RANGES[r] ? r : "7d"; } catch { return "7d"; } };
  const setRange = r => { try { sessionStorage.setItem(RANGE_KEY, r); } catch { /* per-tab preference only */ } };
  const stamp = id => text(id, `Refreshed ${new Date().toLocaleTimeString()}`);
  // "As of <time>" for a precomputed answer: the instant the numbers were computed, how old that
  // is, and whether a newer snapshot is on its way. Falls back to the plain refresh stamp for a
  // server that does not send snapshot metadata.
  function asOfStamp(id, data) {
    const snap = data && data.snapshot;
    if (!snap) return stamp(id);
    if (snap.state === "pending") return text(id, "Computing the first snapshot…");
    const at = new Date(data.as_of || snap.computed_at);
    if (Number.isNaN(at.getTime())) return stamp(id);
    const age = Math.max(0, Math.round(Number(snap.age_seconds) || 0));
    const ago = age < 90 ? `${age}s ago` : age < 5400 ? `${Math.round(age / 60)} min ago` : `${Math.round(age / 3600)} h ago`;
    text(id, `As of ${at.toLocaleTimeString()} (${ago}${snap.state === "stale" ? ", refreshing" : ""})`);
  }
  const notice = (kind, title, body) => `<div class="notice ${kind}"><b>${esc(title)}</b> ${esc(body)}</div>`;
  const unavailableBox = what => `<div class="emptyState unavailableState"><b>${esc(NOT_AVAILABLE)}</b><span>${esc(what)}</span></div>`;
  const isNum = v => v !== null && v !== undefined && v !== "" && Number.isFinite(Number(v));
  const initials = name => String(name || "?").replace(/[^A-Za-z0-9 ]/g, "").split(/\s+/).filter(Boolean).slice(0, 2).map(w => w[0]).join("").toUpperCase() || "?";
  function syncRangePickers() {
    const r = getRange();
    document.querySelectorAll(".rangePicker [data-range]").forEach(b => b.setAttribute("aria-checked", String(b.dataset.range === r)));
  }

  // ---------- router ----------
  function parseHash() {
    let raw = location.hash.replace(/^#/, "");
    try { raw = decodeURIComponent(raw); } catch { /* keep the raw hash */ }
    if (raw && !raw.startsWith("/")) return { legacy: LEGACY[raw] || "dashboard" };
    const [pathPart, queryPart = ""] = raw.replace(/^\//, "").split("?");
    const path = pathPart.replace(/\/+$/, "");
    const query = new URLSearchParams(queryPart);
    const match = /^customers\/(.+)$/.exec(path);
    if (match) return { key: "customer-360", path, org: match[1], query, raw };
    if (ALIASES[path]) {
      const q = new URLSearchParams(queryPart);
      if (ALIAS_FOCUS[path] && !q.has("focus")) q.set("focus", ALIAS_FOCUS[path]);
      return { alias: ALIASES[path] + (q.toString() ? `?${q}` : "") };
    }
    return { key: ROUTES[path] ? path : "", path, org: "", query, raw };
  }
  function go(route) {
    const target = `#/${String(route).replace(/^#?\/?/, "")}`;
    if (location.hash === target) render(true);
    else location.hash = target;
  }
  function render(force = false) {
    const parsed = parseHash();
    if (parsed.legacy) { history.replaceState(null, "", `#/${parsed.legacy}`); return render(); }
    if (parsed.alias) { history.replaceState(null, "", `#/${parsed.alias}`); return render(); }
    if (!parsed.key) { history.replaceState(null, "", "#/dashboard"); return render(); }
    if (!A.isConnected()) return;
    const changed = parsed.raw !== current.raw;
    current = parsed;
    const def = ROUTES[parsed.key];
    const page = def.page || parsed.key;
    document.querySelectorAll("[data-page]").forEach(section => { section.hidden = section.dataset.page !== page; });
    text("adminViewEyebrow", def.group || def.eyebrow || "Platform operations");
    text("adminViewTitle", def.title);
    text("adminViewDescription", def.desc);
    renderCrumbs(def, parsed);
    S.setCurrent(parsed.path);
    document.title = `${def.title} | Morrow administration`;
    if (changed) {
      document.querySelectorAll(".deepLinkNote").forEach(n => n.remove());
      document.querySelectorAll("[data-deep-link-selected]").forEach(el => { el.removeAttribute("data-deep-link-selected"); el.classList.remove("deepLinkHit"); });
      window.scrollTo(0, 0);
      // hashchange fires after location.hash has already changed, so an overlay opened in between
      // (the Ctrl+K palette, a dialog) must keep focus rather than lose it to the new page title.
      const inOverlay = document.activeElement?.closest?.(".sh-palette, dialog, [role=dialog], [aria-modal=true]");
      if (pendingFocus && !inOverlay) $("adminViewTitle")?.focus({ preventScroll: true });
    }
    pendingFocus = true;
    handleQuery(parsed);
    if (changed || force) {
      const loading = loadPage(parsed.key);
      loading.catch(err => A.setStatus(err.message || String(err), "bad"));
      selectRecord(parsed, loading).catch(err => A.setStatus(err.message || String(err), "bad"));
    }
  }
  function renderCrumbs(def, parsed, orgName) {
    const parts = [`<li><a href="#/dashboard">Console</a></li>`];
    if (def.group) {
      const group = S.IA.find(g => g.label === def.group);
      const first = group?.items?.find(i => !i.url);
      parts.push(`<li>${first ? `<a href="#/${esc(first.route)}">${esc(def.group)}</a>` : esc(def.group)}</li>`);
    }
    if (parsed.key === "customer-360" && parsed.org) {
      parts.push(`<li><a href="#/customers">Organizations</a></li>`);
      parts.push(`<li><span aria-current="page">${esc(orgName || parsed.org)}</span></li>`);
    } else parts.push(`<li><span aria-current="page">${esc(def.title)}</span></li>`);
    $("crumbs").innerHTML = parts.join("");
  }
  function handleQuery(parsed) {
    const q = parsed.query;
    if (parsed.key === "customers" && q.get("create")) {
      toggleCreate(true);
      history.replaceState(null, "", "#/customers");
      current.raw = "/customers";
    }
    if (parsed.key === "announcements" && q.get("new")) {
      history.replaceState(null, "", "#/announcements");
      current.raw = "/announcements";
      setTimeout(() => $("annTitle")?.focus(), 0);
    }
    // Search results and notifications deep-link with a filter or a record id; selectRecord
    // finds the record once the page has loaded.
    if (parsed.key === "users" && q.get("q") !== null) $("accessSearch").value = q.get("q");
  }

  // ---------- deep links to one record ----------
  /* Notifications and search results link to a record (#/feedback?id=12, #/api-keys?id=…,
     #/users?q=<email>, #/support-sessions?org=… or ?id=…, #/customers/<org>, …). Once the page's
     data has loaded the record is scrolled into view, highlighted for a moment (a steady tint
     under reduced motion), given focus for keyboard and screen-reader users, and its detail opened
     where the page has one. Filters that hide it are cleared first. A record that still is not
     there gets a "This item no longer exists" note instead of a silent landing on the list. The
     query is then dropped with replaceState, so a refresh, or coming back to the entry, does not
     act (or open anything) again. */
  const reduceMotion = matchMedia("(prefers-reduced-motion: reduce)");
  const recordsIn = (page, test) => [...document.querySelectorAll(`[data-page="${page}"] [data-record-id]`)].filter(test);
  const byRecordId = (page, id) => recordsIn(page, el => el.dataset.recordId === String(id));
  async function clearFilters(ids, reload) {
    const set = ids.map(id => $(id)).filter(el => el && el.value);
    if (!set.length) return false;
    set.forEach(el => { el.value = ""; });
    await reload();
    return true;
  }
  const openDetails = el => { const details = el?.querySelector("details"); if (details) details.open = true; };
  const DEEP_LINKS = {
    feedback: {
      params: ["id"], find: id => byRecordId("feedback", id), open: openDetails,
      // Past the filters and the newest 200: the API returns at most 500. Past that, one read of the
      // item itself (GET /platform/feedback/{id}) shows it in place, so only a real 404 is "missing".
      widen: async id => {
        ["feedbackStatus", "feedbackCategory", "feedbackOrg"].forEach(name => { if ($(name)) $(name).value = ""; });
        await A.loadFeedback({ limit: 500 });
        if (!byRecordId("feedback", id).length) {
          try { await A.loadFeedbackItem(id); } catch (err) { if (err.status !== 404) throw err; }
        }
        return true;
      },
      missing: id => `Feedback #${id} was not found on this server. It has been deleted.`
    },
    "api-keys": {
      params: ["id"], find: id => byRecordId("api-keys", id),
      widen: () => clearFilters(["keysOrg", "keysStatus"], () => A.loadViewData("api-keys")),
      missing: id => `API key ${id} was not found. It may have been deleted.`
    },
    announcements: {
      params: ["id"], find: id => byRecordId("announcements", id),
      missing: id => `Announcement #${id} was not found. It may have been deleted.`
    },
    autopatch: {
      params: ["id"], find: id => byRecordId("autopatch", id),
      widen: () => clearFilters(["autopatchStatus"], () => A.loadAutopatches()),
      // The review panel opens from the API even when the item is past the list's newest 100.
      detail: async id => {
        try { await A.showAutopatch(id); return $("autopatchDetail"); }
        catch (err) { if (err.status === 404 || err.status === 422) return null; throw err; }
      },
      missing: id => `Autopatch #${id} was not found. It may have been deleted.`
    },
    users: {
      params: ["q"],
      find: q => {
        const want = String(q).toLowerCase();
        const exact = recordsIn("users", el => el.dataset.recordEmail.toLowerCase() === want || el.dataset.recordId.toLowerCase() === want);
        if (exact.length) return exact;
        // One partial match is still that user (a renamed account, a search by id fragment).
        const all = recordsIn("users", () => true);
        return all.length === 1 ? all : [];
      },
      widen: () => clearFilters(["accessOrg"], () => A.loadViewData("users")),
      missing: q => `No user matches "${q}". The account may have been removed.`
    },
    "support-sessions": {
      params: ["id", "org"],
      find: (value, param) => param === "id" ? byRecordId("support-sessions", value)
        : recordsIn("support-sessions", el => el.dataset.recordOrg === value).sort((a, b) => Boolean(b.dataset.recordActive) - Boolean(a.dataset.recordActive)),
      widen: (value, param) => clearFilters(param === "id" ? ["supportFilterStatus", "supportFilterOperator", "supportFilterOrg"] : ["supportFilterStatus", "supportFilterOperator"], () => window.AdminSupport?.loadPage() || Promise.resolve()),
      open: (el, value, param) => { if (param === "id") openDetails(el); },
      missing: (value, param) => param === "id" ? `Support session ${value} was not found.` : `No support session for ${value} was found. It may have been purged.`
    },
    jobs: {
      params: ["id"], find: id => byRecordId("jobs", id), open: openDetails,
      missing: id => `Job ${id} is not registered on this server.`
    },
    "alert-routing": {
      params: ["id"], find: id => byRecordId("alert-routing", id),
      missing: id => `Alert channel ${id} was not found. It may have been deleted.`
    },
    // A notification about a panel rather than a row (#/readiness, #/abuse, #/logins).
    launch: { params: ["focus"], find: id => focusPanel("launch", id) },
    incidents: { params: ["focus"], find: id => focusPanel("incidents", id) },
    audit: { params: ["focus"], find: id => focusPanel("audit", id) },
    "customer-360": {
      find: org => (c360Data && c360Data.org === org ? [$("c360Name").closest(".c360Head")] : []),
      // load360 already explains a missing organization in place; that note gets the focus.
      missingHere: org => c360Missing === org ? $("c360Notice").firstElementChild : null
    }
  };
  function focusPanel(page, id) {
    const el = $(id);
    const panel = el && el.closest(`[data-page="${page}"]`) ? el.closest(".card") || el : null;
    return panel ? [panel] : [];
  }
  let deepSeq = 0;
  async function selectRecord(parsed, loading) {
    const spec = DEEP_LINKS[parsed.key];
    if (!spec) return;
    let value = "", param = "";
    if (parsed.key === "customer-360") value = parsed.org;
    else for (const name of spec.params) { if (parsed.query.get(name)) { value = parsed.query.get(name); param = name; break; } }
    if (!value) return;
    const seq = ++deepSeq;
    const here = () => seq === deepSeq && current.raw === parsed.raw;
    try { await loading; } catch { return; }   // the page shows its own failure state
    if (!here()) return;
    let found = spec.find(value, param);
    if (!found.length && spec.widen) {
      if (await spec.widen(value, param)) { if (!here()) return; found = spec.find(value, param); }
    }
    const detail = spec.detail ? await spec.detail(value) : null;
    if (!here()) return;
    const page = spec.page || parsed.key;
    if (found.length || detail) {
      document.querySelectorAll("[data-deep-link-selected]").forEach(el => el.removeAttribute("data-deep-link-selected"));
      const targets = found.length ? found : [detail];
      targets.forEach(flash);
      if (found.length) spec.open?.(found[0], value, param);
      bringIntoFocus(targets[0]);
    } else if (spec.missingHere) {
      const note = spec.missingHere(value);
      if (note) bringIntoFocus(note);
    } else if (spec.missing) showMissing(page, spec.missing(value, param));
    if (parsed.query.toString()) {
      history.replaceState(history.state, "", `#/${parsed.path}`);
      current = { ...current, raw: `/${parsed.path}`, query: new URLSearchParams() };
    }
  }
  function flash(el) {
    el.setAttribute("data-deep-link-selected", "");
    el.classList.remove("deepLinkHit");
    void el.offsetWidth;   // restart the highlight when the same record is linked again
    el.classList.add("deepLinkHit");
    clearTimeout(el.__deepLinkTimer);
    el.__deepLinkTimer = setTimeout(() => el.classList.remove("deepLinkHit"), 2600);
  }
  function bringIntoFocus(el) {
    if (!el.matches("a[href], button, input, select, textarea, [tabindex]")) el.setAttribute("tabindex", "-1");
    el.focus({ preventScroll: true });
    el.scrollIntoView({ block: "center", behavior: reduceMotion.matches ? "auto" : "smooth" });
  }
  function showMissing(pageKey, message) {
    const section = document.querySelector(`[data-page="${pageKey}"]`);
    if (!section) return;
    section.querySelectorAll(".deepLinkNote").forEach(n => n.remove());
    const note = document.createElement("div");
    note.className = "notice warn deepLinkNote";
    note.setAttribute("role", "alert");
    note.innerHTML = `<b>This item no longer exists.</b> <span>${esc(message)}</span> <button class="btn secondary small" type="button" data-deep-link-dismiss>Dismiss</button>`;
    section.prepend(note);
    bringIntoFocus(note);
  }
  document.addEventListener("click", event => {
    const button = event.target.closest("[data-deep-link-dismiss]");
    if (!button) return;
    const note = button.closest(".deepLinkNote");
    note.remove();
    $("adminViewTitle")?.focus({ preventScroll: true });
  });
  window.addEventListener("hashchange", () => render());

  const loaders = {
    dashboard: () => loadDashboard(),
    customers: async () => { stamp("orgRefreshed"); },
    "customer-360": () => (current.org ? load360(current.org) : renderPicker()),
    onboarding: () => loadOnboarding(),
    "support-sessions": async () => { await window.AdminSupport?.loadPage(); },
    feedback: () => A.loadFeedback(),
    trials: () => A.loadTrialRequests(),
    usage: () => loadUsage(),
    flags: () => loadFlagsCatalog(),
    operators: async () => { renderWhoami(); await A.loadViewData("operators"); },
    launch: () => A.loadGate(),
    jobs: () => loadJobs(),
    "alert-routing": () => (window.AdminAlerts ? window.AdminAlerts.load() : Promise.resolve()),
    autopatch: () => A.loadAutopatches(),
    notifications: () => (S.notifications.status === "idle" ? S.loadNotifications() : renderNotificationsPage())
  };
  async function loadPage(key) {
    const tasks = [];
    if (loaders[key]) tasks.push(loaders[key]());
    tasks.push(A.loadViewData(key));
    const results = await Promise.allSettled(tasks);
    const failed = results.find(r => r.status === "rejected");
    if (failed) throw failed.reason;
  }

  // ---------- connection ----------
  function moveInto(id, slotId) { const el = $(id), slot = $(slotId); if (el && slot && el.parentElement !== slot) slot.appendChild(el); }
  document.addEventListener("admin:connected", () => {
    document.body.dataset.auth = "signed-in";
    $("signinScreen").hidden = true;
    $("appShell").hidden = false;
    moveInto("roleField", "roleMenuSlot");
    moveInto("roleBindingNote", "noteMenuSlot");
    moveInto("status", "statusLine");
    A.applyRoleControls();
    updateCounts();
    pendingFocus = false;
    render(true);
    S.loadNotifications();
  });
  document.addEventListener("admin:snapshot", () => {
    updateCounts();
    if (current.key && current.key !== "customers") loadPage(current.key).catch(err => A.setStatus(err.message || String(err), "bad"));
    else stamp("orgRefreshed");
  });
  document.addEventListener("admin:role", () => { if (current.key === "operators") renderWhoami(); });

  // ---------- counts in the menus ----------
  let lastKpis = null;
  function updateCounts() {
    const metrics = A.metrics() || {};
    const orgs = A.customers();
    const feedbackOpen = /^(\d[\d,]*) open/.exec($("feedbackCount")?.textContent || "");
    const trialsPending = /^(\d[\d,]*) pending/.exec($("trialCount")?.textContent || "");
    const incidents = A.incidentsSummary();
    const kpi = key => (lastKpis && lastKpis[key] && isNum(lastKpis[key].value) ? Number(lastKpis[key].value) : null);
    const maintenanceOn = !$("maintenancePill")?.hidden;
    S.setCounts({
      organizations: orgs.length ? fmt.format(orgs.length) : null,
      atRisk: (metrics.churn_risk || []).length || null,
      openFeedback: kpi("open_feedback") ?? (feedbackOpen ? Number(feedbackOpen[1].replace(/,/g, "")) : null),
      pendingTrials: trialsPending ? (Number(trialsPending[1].replace(/,/g, "")) || null) : null,
      activeKeys: kpi("active_api_keys"),
      activeSessions: kpi("active_sessions"),
      incidents: incidents ? incidents.incidents || null : null,
      pendingAutopatches: kpi("pending_autopatches"),
      maintenance: maintenanceOn ? "on" : null
    }, { atRisk: "warn", openFeedback: "warn", incidents: "bad", pendingAutopatches: "warn", maintenance: "bad" });
  }

  // ---------- range pickers ----------
  document.addEventListener("click", event => {
    const button = event.target.closest(".rangePicker [data-range]");
    if (!button) return;
    setRange(button.dataset.range);
    syncRangePickers();
    if (current.key === "dashboard") loadDashboard().catch(err => A.setStatus(err.message, "bad"));
    if (current.key === "usage") loadUsage().catch(err => A.setStatus(err.message, "bad"));
  });
  document.addEventListener("keydown", event => {
    const button = event.target.closest?.(".rangePicker [data-range]");
    if (!button || !["ArrowLeft", "ArrowRight"].includes(event.key)) return;
    event.preventDefault();
    const all = [...button.parentElement.querySelectorAll("[data-range]")];
    const next = all[(all.indexOf(button) + (event.key === "ArrowRight" ? 1 : -1) + all.length) % all.length];
    next.focus(); next.click();
  });
  syncRangePickers();

  // Retry keys owned by this module.
  const retry = { dashboard: () => loadDashboard(), c360: () => current.org && load360(current.org), usage: () => loadUsage(), jobs: () => loadJobs(), notifications: () => S.loadNotifications(), flags: () => loadFlagsCatalog(), onboarding: () => loadOnboarding() };
  document.addEventListener("click", event => {
    const button = event.target.closest("[data-retry]");
    if (!button || !retry[button.dataset.retry]) return;
    button.disabled = true;
    Promise.resolve().then(retry[button.dataset.retry]).catch(err => A.setStatus(err.message || String(err), "bad"));
  });

  // ---------- KPI tiles ----------
  const KPI_ORDER = ["organizations", "active_organizations", "new_organizations", "users", "active_users", "new_users", "logins", "failed_logins", "api_requests", "error_rate_pct", "p95_latency_ms", "rate_limited_requests", "scans", "assets", "open_remediations", "open_feedback", "pending_autopatches", "active_api_keys", "active_sessions", "admin_actions"];
  const KPI_LABELS = { organizations: "Organizations", active_organizations: "Active organizations", new_organizations: "New organizations", users: "Users", active_users: "Active users", new_users: "New users", logins: "Sign-ins", failed_logins: "Failed sign-ins", api_requests: "API requests", error_rate_pct: "Error rate", p95_latency_ms: "p95 latency", rate_limited_requests: "Rate limited", scans: "Scans", assets: "Assets", open_remediations: "Open remediations", open_feedback: "Open feedback", pending_autopatches: "Pending autopatches", active_api_keys: "Active API keys", active_sessions: "Active sessions", admin_actions: "Admin actions" };
  const UP_IS_BAD = new Set(["failed_logins", "error_rate_pct", "p95_latency_ms", "rate_limited_requests", "open_feedback", "pending_autopatches", "open_remediations", "failed"]);
  const NEUTRAL = new Set(["admin_actions", "active_sessions", "active_api_keys"]);
  const kpiFormat = key => (key === "error_rate_pct" ? C.formats.pct : key === "p95_latency_ms" ? C.formats.ms : C.compact);
  function sparkFor(key, series) {
    if (!series) return null;
    const pick = (name, field = "value") => (Array.isArray(series[name]) ? series[name].map(p => p?.[field]) : null);
    switch (key) {
      case "new_organizations": return pick("signups", "organizations");
      case "new_users": return pick("signups", "users");
      case "active_users": return pick("active_users");
      case "logins": return pick("logins", "success");
      case "failed_logins": return pick("logins", "failed");
      case "scans": return pick("scans");
      case "api_requests": return pick("requests", "total");
      case "rate_limited_requests": return pick("requests", "rate_limited");
      case "p95_latency_ms": return pick("latency", "p95");
      case "admin_actions": return pick("admin_actions");
      case "error_rate_pct": return Array.isArray(series.requests) ? series.requests.map(p => (asNum(p?.total) ? (asNum(p.server_errors) / asNum(p.total)) * 100 : null)) : null;
      default: return null;
    }
  }
  function kpiTile(key, k, series, reasons, rangeLabel) {
    const label = k?.label || KPI_LABELS[key] || key.replace(/_/g, " ");
    const f = kpiFormat(key);
    if (!k || !isNum(k.value)) {
      const why = reasons[key] || (k ? "No value for this range, for example a rate with no requests." : "This server does not track it.");
      return `<div class="kpi off" data-kpi="${esc(key)}"><div class="kpiLabel">${esc(label)}</div><div class="kpiValue">&mdash;</div><div class="kpiFoot" title="${esc(why)}">${k ? "No data in range" : "Not tracked"}</div></div>`;
    }
    let delta = `<span class="delta flat">no prior data</span>`;
    if (isNum(k.delta_pct)) {
      const d = Number(k.delta_pct);
      const dir = d > 0.05 ? "up" : d < -0.05 ? "down" : "flat";
      const tone = dir === "flat" || NEUTRAL.has(key) ? "neutral" : (dir === "up") !== UP_IS_BAD.has(key) ? "good" : "bad";
      delta = `<span class="delta ${dir} ${tone}" title="Compared with the previous ${esc(rangeLabel)}"><span aria-hidden="true">${dir === "up" ? "&#9650;" : dir === "down" ? "&#9660;" : "&#9644;"}</span> ${esc(`${Math.abs(d) >= 100 ? Math.round(Math.abs(d)) : Math.abs(d).toFixed(1)}%`)}</span>`;
    } else if (isNum(k.previous) && Number(k.previous) === 0 && Number(k.value) > 0) delta = `<span class="delta flat">new this period</span>`;
    const prevWhy = reasons[`${key}.previous`];
    if (!isNum(k.previous) && prevWhy) delta = `<span class="delta flat" title="${esc(prevWhy)}">no prior period</span>`;
    const prev = isNum(k.previous) ? `<span class="kpiPrev">prev ${esc(f(k.previous))}</span>` : "";
    const spark = C.sparkline(sparkFor(key, series) || []);
    return `<div class="kpi" data-kpi="${esc(key)}"${k.source ? ` title="${esc(`Source: ${k.source}`)}"` : ""}><div class="kpiLabel">${esc(label)}</div><div class="kpiValue">${esc(f(k.value))}</div><div class="kpiFoot">${delta}${prev}</div>${spark ? `<div class="kpiSpark">${spark}</div>` : ""}</div>`;
  }

  // ---------- series adapters ----------
  // Overview buckets report 429s in rate_limited and exclude them from client_errors; customer
  // buckets have no rate_limited field and count 429s as client errors. Buckets older than the
  // request journal's retention are null: they stay null so the chart leaves a gap, never a zero.
  function requestSeries(rows = []) {
    return (rows || []).map(p => {
      if (!p || p.total === null || p.total === undefined) return { t: p?.t, ok: null, client: null, limited: null, server: null };
      const total = asNum(p.total), client = asNum(p.client_errors), server = asNum(p.server_errors);
      const limited = isNum(p.rate_limited) ? Number(p.rate_limited) : null;
      return { t: p.t, ok: Math.max(0, total - client - server - (limited || 0)), client, limited, server };
    });
  }
  const REQUEST_SERIES = [
    { key: "ok", label: "Successful", color: "--c-iris" },
    { key: "client", label: "Client errors (4xx)", color: "--c-orange" },
    { key: "limited", label: "Rate limited (429)", color: "--c-aqua" },
    { key: "server", label: "Server errors (5xx)", color: "--c-red" }
  ];
  const CUSTOMER_REQUEST_SERIES = REQUEST_SERIES.filter(s => s.key !== "limited").map(s => (s.key === "client" ? { ...s, label: "Client errors (4xx incl. 429)" } : s));
  // "Request data retained from ..." when the journal does not cover the whole range.
  function coverageNote(coverage, source) {
    const c = coverage && coverage[source];
    if (!c || c.range_complete !== false) return "";
    return `${source === "platform_request_events" ? "Request" : "Sign-in"} data is retained from ${fmtTime(c.retained_from, "an unknown date")}; earlier buckets are unknown and left blank.`;
  }
  const LOGIN_SERIES = [{ key: "success", label: "Successful", color: "--c-iris" }, { key: "failed", label: "Failed", color: "--c-red" }];
  function chartUnavailable(id, what) { const host = $(id); if (host) host.innerHTML = unavailableBox(what); }

  // ---------- dashboard ----------
  let dashSeq = 0, dashData = null;
  async function loadDashboard() {
    const seq = ++dashSeq;
    const range = getRange();
    const page = document.querySelector('[data-page="dashboard"]');
    if (!dashData) $("kpiGrid").innerHTML = Array.from({ length: 10 }, () => `<div class="kpi"><span class="skel"></span><span class="skel wide"></span></div>`).join("");
    else page.classList.add("refetching");
    const [overview] = await Promise.all([A.safeApi(`/platform/analytics/overview?range=${enc(range)}`)]);
    if (seq !== dashSeq) return;
    page.classList.remove("refetching");
    // The overview is precomputed on a schedule, so the useful timestamp is when the numbers were
    // computed -- not when this browser asked for them, which is all "Refreshed 14:02:11" ever said.
    asOfStamp("dashRefreshed", overview.ok ? overview.data : null);
    const unavailable = [];
    if (!overview.ok) {
      dashData = null;
      lastKpis = null;
      $("snapshotTotals").hidden = false;
      if (overview.status === 404) {
        $("dashNotice").innerHTML = notice("warn", "Analytics are not available on this server yet.", "Trends, deltas and top lists need GET /platform/analytics/overview. The platform status and all-time totals further down come from the existing snapshot and are real.");
        $("kpiGrid").innerHTML = "";
        unavailable.push(["Analytics overview (KPIs, trends, top lists)", "GET /platform/analytics/overview is not deployed on this server."]);
      } else {
        $("dashNotice").innerHTML = failBox(`Analytics could not be loaded: ${overview.error}`, "dashboard");
        $("kpiGrid").innerHTML = "";
      }
      const what = overview.status === 404 ? "Needs the analytics overview endpoint." : "Analytics failed to load.";
      ["chartSignups", "chartActive", "chartRequests", "chartLatency", "chartLogins", "chartScans"].forEach(id => chartUnavailable(id, what));
      $("topOrgsBody").innerHTML = emptyRow(5, overview.status === 404 ? NOT_AVAILABLE : "Unavailable.");
      $("routesBody").innerHTML = emptyRow(4, overview.status === 404 ? NOT_AVAILABLE : "Unavailable.");
      renderPlans(null);
    } else {
      const d = overview.data || {};
      dashData = d;
      lastKpis = d.kpis || {};
      $("dashNotice").innerHTML = "";
      $("snapshotTotals").hidden = true;
      const reasons = Object.fromEntries((d.unavailable || []).map(u => [u.metric, u.reason]));
      const rangeLabel = RANGES[range];
      $("kpiGrid").innerHTML = KPI_ORDER.concat(Object.keys(lastKpis).filter(k => !KPI_ORDER.includes(k))).map(key => kpiTile(key, lastKpis[key], d.series, reasons, rangeLabel)).join("");
      const s = d.series || {}, bucket = d.bucket;
      const series = (id, cfg) => C.timeSeries($(id), { bucket, ...cfg });
      series("chartSignups", { label: "Signups", kind: "line", data: s.signups || [], series: [{ key: "organizations", label: "Organizations", color: "--c-iris" }, { key: "users", label: "Users", color: "--c-aqua" }] });
      series("chartActive", { label: "Active users", kind: "area", data: s.active_users || [], series: [{ key: "value", label: "Active users", color: "--c-iris" }] });
      series("chartRequests", { label: "API requests", kind: "stacked", data: requestSeries(s.requests), series: REQUEST_SERIES, format: "count", caption: coverageNote(d.coverage, "platform_request_events") });
      series("chartLatency", { label: "Latency", kind: "line", format: "ms", data: s.latency || [], series: [{ key: "p50", label: "p50", color: "--c-aqua" }, { key: "p95", label: "p95", color: "--c-iris" }], caption: coverageNote(d.coverage, "platform_request_events") });
      series("chartLogins", { label: "Sign-ins", kind: "stacked", data: s.logins || [], series: LOGIN_SERIES, caption: coverageNote(d.coverage, "platform_auth_events") });
      series("chartScans", { label: "Scans", kind: "columns", data: s.scans || [], series: [{ key: "value", label: "Scans", color: "--c-iris" }] });
      const top = d.top || {};
      const orgs = top.organizations_by_activity || [];
      $("topOrgsBody").innerHTML = orgs.length ? orgs.map(o => `<tr class="customerRow" data-org-link="${esc(o.organization_id)}" tabindex="0"><td><b>${esc(o.name || o.organization_id)}</b><br><span class="mono muted">${esc(o.organization_id)}</span></td><td class="num">${esc(C.compact(o.requests))}</td><td class="num">${esc(C.compact(o.logins))}</td><td class="num">${esc(C.compact(o.scans))}</td><td class="mono">${esc(fmtTime(o.last_seen, "Not observed"))}</td></tr>`).join("") : emptyRow(5, `No organization activity in the ${rangeLabel}.`);
      const routes = top.routes_by_errors || [];
      $("routesBody").innerHTML = routes.length ? routes.map(r => `<tr><td class="mono">${esc(r.route)}</td><td class="num">${esc(C.compact(r.requests))}</td><td class="num">${esc(C.compact(r.errors))}</td><td class="num">${esc(C.formats.pct(r.error_rate_pct))}</td></tr>`).join("") : emptyRow(4, `No server errors in the ${rangeLabel}.`);
      renderPlans(top.plans);
      (d.unavailable || []).forEach(u => unavailable.push([metricName(u.metric), u.reason || "Not tracked by this server."]));
      KPI_ORDER.forEach(key => { if (!lastKpis[key]) unavailable.push([KPI_LABELS[key], "Not returned by this server."]); else if (!isNum(lastKpis[key].value) && !reasons[key]) unavailable.push([KPI_LABELS[key], "No value for this range, for example a rate with no requests."]); });
    }
    if (S.notifications.status === "unavailable") unavailable.push(["Notifications", "GET /platform/notifications is not deployed on this server."]);
    $("unavailCount").textContent = String(unavailable.length);
    $("unavailableBody").innerHTML = `<ul class="unavailList">${unavailable.map(([m, why]) => `<li><b>${esc(m)}</b><span>${esc(why)}</span></li>`).join("")}</ul>`;
    renderAttention();
    updateCounts();
  }
  const FEATURE_LABELS = { tls_scans: "TLS scans", assets: "Asset inventory", remediations: "Remediations", cbom_ingest: "CBOM ingest", github: "GitHub", sbom: "SBOM imports", mobile_iot: "Mobile & IoT scans", zk_proofs: "ZK compliance proofs", vendor_attestations: "Vendor attestations", hndl_canaries: "HNDL canaries", quantum_canaries: "Quantum canaries", scan_schedules: "Scan schedules", webhooks: "Webhooks", ai_assistant: "AI assistant", api_keys: "API keys" };
  function featureLabel(key) { return FEATURE_LABELS[key] || String(key || "").replace(/_/g, " ").replace(/^\w/, ch => ch.toUpperCase()); }
  function metricName(metric) {
    const m = String(metric || "");
    const parts = m.split(".");
    if (parts[0] === "feature") return `${featureLabel(parts[1])}${parts[2] ? ` (${parts[2].replace(/_/g, " ")})` : ""}`;
    const label = KPI_LABELS[parts[0]] || parts[0].replace(/_/g, " ");
    if (parts[1] === "previous") return `${label} (previous period)`;
    return parts[1] ? `${label} (${parts[1].replace(/_/g, " ")})` : label;
  }
  function renderPlans(plans) {
    const host = $("plansBody");
    let rows = Array.isArray(plans) ? plans.map(p => ({ k: p.plan || "unassigned", v: asNum(p.organizations) })) : Object.entries((A.metrics() || {}).plan_breakdown || {}).map(([k, v]) => ({ k, v: asNum(v) }));
    rows = rows.filter(r => r.v > 0).sort((a, b) => b.v - a.v);
    if (!rows.length) { host.innerHTML = A.isConnected() && (A.customers() || []).length === 0 ? empty("No organizations yet.") : empty("No plan data available."); return; }
    const PALETTE = ["--c-iris", "--c-orange", "--c-aqua", "--c-yellow", "--c-magenta", "--c-blue", "--c-green", "--c-red"];
    if (rows.length > 8) { const rest = rows.slice(7).reduce((n, r) => n + r.v, 0); rows = rows.slice(0, 7).concat([{ k: "Other", v: rest }]); }
    const total = rows.reduce((n, r) => n + r.v, 0);
    const segs = rows.map((r, i) => ({ k: r.k, v: r.v, f: fmt.format(r.v), p: `${Math.round((r.v / total) * 100)}%`, c: `var(${PALETTE[i]})` }));
    const fallback = `<ul class="planList">${rows.map((r, i) => `<li><i style="background:var(${PALETTE[i]})"></i><span>${esc(r.k)}</span><b>${fmt.format(r.v)}</b><small>${Math.round((r.v / total) * 100)}%</small></li>`).join("")}</ul>`;
    const cfg = { segs, center: fmt.format(total), sub: "organizations" };
    host.innerHTML = `<div class="c3d" data-c3d="donut" data-c3d-cfg="${esc(JSON.stringify(cfg))}">${fallback}</div>`;
  }
  function renderAttention() {
    const host = $("attentionBody");
    if (!host) return;
    const notes = S.notifications;
    if (notes.status === "loading" && !notes.data) { host.innerHTML = skeletonList(3); return; }
    if (notes.status === "unavailable") { host.innerHTML = `<div class="emptyState unavailableState"><b>${esc(NOT_AVAILABLE)}</b><span>Notifications need GET /platform/notifications. Until then, check <a href="#/health">Service health</a> and <a href="#/launch">Launch readiness</a>.</span></div>`; return; }
    if (notes.status === "error") { host.innerHTML = failBox(`Notifications could not be loaded: ${notes.error}`, "notifications"); return; }
    const order = { critical: 0, warn: 1, info: 2 };
    const items = (notes.data?.items || []).slice().sort((a, b) => order[S.severity(a)] - order[S.severity(b)]).slice(0, 6);
    if (!items.length) { host.innerHTML = `<div class="emptyState"><b>All clear</b><span>No open notifications.</span></div>`; return; }
    host.innerHTML = `<ul class="attention">${items.map(item => `<li class="${S.isRead(item.id) ? "read" : ""}"><span class="sev ${esc(S.severity(item))}" aria-label="${esc(S.severity(item))}"></span><a href="${esc(S.routeHref(item.route) || "#/notifications")}"><b>${esc(item.title || item.kind)}</b>${item.detail ? `<small>${esc(item.detail)}</small>` : ""}</a><time>${esc(S.relTime(item.created_at))}</time></li>`).join("")}</ul>`;
  }
  document.addEventListener("shell:notifications", () => {
    renderAttention();
    if (current.key === "notifications") renderNotificationsPage();
  });
  $("dashRefreshBtn")?.addEventListener("click", () => { loadDashboard().catch(err => A.setStatus(err.message, "bad")); S.loadNotifications(); });
  // Auto-refresh the dashboard every 60s while it is the visible page and the tab is showing.
  setInterval(() => { if (A.isConnected() && !document.hidden && current.key === "dashboard") loadDashboard().catch(() => {}); }, 60000);
  document.addEventListener("click", event => {
    const row = event.target.closest("[data-org-link]");
    if (row) location.hash = `#/customers/${enc(row.dataset.orgLink)}`;
  });
  document.addEventListener("keydown", event => {
    const row = event.target.closest?.("[data-org-link]");
    if (row && (event.key === "Enter" || event.key === " ")) { event.preventDefault(); location.hash = `#/customers/${enc(row.dataset.orgLink)}`; }
  });

  // ---------- organizations ----------
  function toggleCreate(open) {
    const card = $("createCustomerCard"), button = $("orgCreateToggle");
    const show = open ?? card.hidden;
    card.hidden = !show;
    button.setAttribute("aria-expanded", String(show));
    button.textContent = show ? "Close form" : "New customer";
    if (show) { card.scrollIntoView({ block: "nearest" }); setTimeout(() => $("newOrgId")?.focus(), 0); }
  }
  $("orgCreateToggle")?.addEventListener("click", () => toggleCreate());

  // ---------- Customer 360 ----------
  let c360Seq = 0, c360Data = null, c360Missing = "";
  function renderPicker() {
    $("c360").hidden = true;
    $("c360Picker").hidden = false;
    const q = ($("c360PickerSearch").value || "").toLowerCase().trim();
    let last = "";
    try { last = sessionStorage.getItem(LAST_ORG_KEY) || ""; } catch { last = ""; }
    const orgs = A.customers().filter(c => !q || `${c.name || ""} ${c.organization_id}`.toLowerCase().includes(q))
      .sort((a, b) => (b.organization_id === last) - (a.organization_id === last) || String(a.name || a.organization_id).localeCompare(String(b.name || b.organization_id)));
    $("c360PickerBody").innerHTML = orgs.length ? `<ul class="pickList">${orgs.slice(0, 60).map(c => `<li><a href="#/customers/${esc(enc(c.organization_id))}"><span class="avatar small" aria-hidden="true">${esc(initials(c.name || c.organization_id))}</span><span><b>${esc(c.name || c.organization_id)}</b><small class="mono">${esc(c.organization_id)}</small></span>${statusPill(c.subscription_status)}${c.organization_id === last ? `<em>recently opened</em>` : ""}</a></li>`).join("")}</ul>` : empty(A.customers().length ? "No organizations match." : "No organizations yet.");
  }
  $("c360PickerSearch")?.addEventListener("input", renderPicker);

  async function load360(org) {
    const seq = ++c360Seq;
    $("c360Picker").hidden = true;
    $("c360").hidden = false;
    try { sessionStorage.setItem(LAST_ORG_KEY, org); } catch { /* optional */ }
    const known = A.customers().find(c => c.organization_id === org);
    const fresh = !c360Data || c360Data.org !== org;
    if (fresh) {
      text("c360Name", known?.name || org); text("c360OrgId", org); text("c360Avatar", initials(known?.name || org));
      $("c360Meta").innerHTML = ""; $("c360Notice").innerHTML = "";
      $("c360Kpis").innerHTML = Array.from({ length: 6 }, () => `<div class="kpi"><span class="skel"></span><span class="skel wide"></span></div>`).join("");
      ["c360Members", "c360Keys", "c360Sessions"].forEach(id => { $(id).innerHTML = skeletonRows(4, 3); });
      ["c360Adoption", "c360Timeline", "c360Onboarding", "c360Flags", "c360Notes", "c360ChartLogins", "c360ChartRequests", "c360ChartScans"].forEach(id => { $(id).innerHTML = skeletonList(3); });
    } else document.querySelector('[data-page="customer360"]').classList.add("refetching");
    const base = `/platform/customers/${enc(org)}`;
    const range = getRange();
    const [detail, analytics, users, keys, sessions, flags] = await Promise.all([
      A.safeApi(base), A.safeApi(`/platform/analytics/customers/${enc(org)}?range=${enc(range)}`), A.safeApi(`${base}/users`),
      A.safeApi(`${base}/api-keys`), A.safeApi(`/platform/sessions?organization_id=${enc(org)}&limit=100`), A.safeApi(`${base}/feature-flags`)
    ]);
    if (seq !== c360Seq || current.org !== org) return;
    document.querySelector('[data-page="customer360"]').classList.remove("refetching");
    if (!detail.ok) {
      c360Data = null;
      c360Missing = detail.status === 404 ? org : "";
      $("c360Notice").innerHTML = detail.status === 404 ? notice("warn", "This item no longer exists.", `No organization with id ${org} exists on this server. It may have been purged.`) : failBox(`Customer could not be loaded: ${detail.error}`, "c360");
      $("c360Kpis").innerHTML = "";
      ["c360Members", "c360Keys", "c360Sessions"].forEach(id => { $(id).innerHTML = emptyRow(4, "Unavailable."); });
      ["c360Adoption", "c360Timeline", "c360Onboarding", "c360Flags", "c360Notes", "c360ChartLogins", "c360ChartRequests", "c360ChartScans"].forEach(id => { $(id).innerHTML = empty("Unavailable."); });
      return;
    }
    const d = detail.data || {};
    const c = d.customer || {};
    const an = analytics.ok ? analytics.data || {} : null;
    c360Data = { org, detail: d, analytics: an };
    c360Missing = "";
    const name = c.name || an?.organization?.name || org;
    text("c360Name", name); text("c360OrgId", org); text("c360Avatar", initials(name));
    renderCrumbs(ROUTES["customer-360"], current, name);
    document.title = `${name} | Customer 360 | Morrow administration`;
    text("adminViewTitle", "Customer 360");
    const status = String(c.subscription_status || an?.organization?.subscription_status || an?.organization?.status || "unknown");
    const lastActivity = an?.last_activity?.at || c.last_login_at;
    const lastKind = an?.last_activity?.kind;
    $("c360Meta").innerHTML = [statusPill(status), `<span><small>Plan</small>${esc(c.plan_type || an?.organization?.plan || "starter")}</span>`, `<span><small>Created</small>${esc(fmtTime(c.created_at || an?.organization?.created_at, "Unknown"))}</span>`, `<span><small>Last activity</small>${esc(fmtTime(lastActivity, "Not observed"))}${lastKind ? ` <span class="muted">(${esc(lastKind)})</span>` : ""}</span>`, an?.organization?.suspended_reason ? `<span><small>Suspended</small>${esc(an.organization.suspended_reason)}${an.organization.suspended_at ? ` · ${esc(fmtTime(an.organization.suspended_at))}` : ""}</span>` : "", c.lifecycle_stage ? `<span><small>Stage</small>${esc(c.lifecycle_stage)}</span>` : "", c.renewal_at ? `<span><small>Renewal</small>${esc(c.renewal_at)}</span>` : ""].join("");
    $("c360SuspendBtn").hidden = status === "suspended" || status === "archived";
    $("c360ResumeBtn").hidden = status !== "suspended" && status !== "archived";
    $("c360ArchiveBtn").hidden = status === "archived";
    $("c360UsersLink").href = "#/users"; $("c360KeysLink").href = "#/api-keys"; $("c360SessionsLink").href = "#/sessions";

    // KPIs: analytics when the server has it, otherwise the customer record's own counts.
    const notes = [];
    if (an) {
      const reasons = Object.fromEntries((an.unavailable || []).map(u => [u.metric, u.reason]));
      const keysOrder = Object.keys(an.kpis || {});
      $("c360Kpis").innerHTML = keysOrder.length ? keysOrder.map(k => kpiTile(k, an.kpis[k], an.series, reasons, RANGES[range])).join("") : "";
    } else {
      if (analytics.status === 404) notes.push(notice("warn", "Per-customer analytics are not available on this server yet.", "Trends and feature adoption need GET /platform/analytics/customers/{org}. Counts below come from the customer record."));
      else notes.push(failBox(`Customer analytics could not be loaded: ${analytics.error}`, "c360"));
      const openRems = Object.entries(d.remediation_status || {}).filter(([s2]) => !/done|closed|resolved|verified/i.test(s2)).reduce((n, [, v]) => n + asNum(v), 0);
      const tile = (label, value, foot) => `<div class="kpi"><div class="kpiLabel">${esc(label)}</div><div class="kpiValue">${value}</div><div class="kpiFoot">${esc(foot)}</div></div>`;
      $("c360Kpis").innerHTML = [tile("Risk score", riskPill(c.risk_score || 0), "activation risk: no sign-in, no scan, no active user, status"), tile("Scans", esc(fmt.format(asNum(c.scan_count))), "all time"), tile("Assets", esc(fmt.format(asNum(c.asset_count))), "tracked surfaces"), tile("Users", esc(fmt.format(asNum(c.user_count))), "accounts and members"), tile("Open remediations", esc(fmt.format(openRems)), "customer work"), tile("Recent sign-ins", esc(fmt.format((d.recent_logins || []).length)), "latest retained")].join("");
    }
    $("c360Notice").innerHTML = notes.join("");

    if (an) {
      const s = an.series || {}, bucket = an.bucket;
      C.timeSeries($("c360ChartLogins"), { bucket, label: "Sign-ins", kind: "stacked", data: s.logins || [], series: LOGIN_SERIES, caption: coverageNote(an.coverage, "platform_auth_events") });
      C.timeSeries($("c360ChartRequests"), { bucket, label: "API requests", kind: "stacked", data: requestSeries(s.requests), series: CUSTOMER_REQUEST_SERIES, caption: coverageNote(an.coverage, "platform_request_events") });
      C.timeSeries($("c360ChartScans"), { bucket, label: "Scans", kind: "columns", data: s.scans || [], series: [{ key: "value", label: "Scans", color: "--c-iris" }] });
    } else ["c360ChartLogins", "c360ChartRequests", "c360ChartScans"].forEach(id => chartUnavailable(id, analytics.status === 404 ? "Needs per-customer analytics." : "Analytics failed to load."));

    // Members
    const members = an?.members || (users.ok ? users.data.items || [] : null);
    $("c360Members").innerHTML = members === null ? failRow(4, `Members unavailable: ${users.error}`, "c360") : members.length ? members.map(u => `<tr><td><div class="cellStack"><b>${esc(u.email || u.user_id)}</b><span class="mono muted">${esc(u.user_id)}</span></div></td><td>${esc(u.role || "—")}</td><td>${statusPill(u.status || "active")}</td><td class="mono">${esc(fmtTime(u.last_login_at, "Not observed"))}</td></tr>`).join("") : emptyRow(4, "No members in this organization yet.");

    // Adoption
    if (an && Array.isArray(an.adoption)) {
      const used = an.adoption.filter(a => a.used).length;
      $("c360Adoption").innerHTML = an.adoption.length ? `<div class="adoptHead"><b>${fmt.format(used)} of ${fmt.format(an.adoption.length)}</b> features used <span class="meter"><i style="width:${Math.round((used / Math.max(1, an.adoption.length)) * 100)}%"></i></span></div><ul class="checklist cols">${an.adoption.map(a => `<li class="${a.used ? "done" : ""}"><span class="tick" aria-hidden="true">${a.used ? "&#10003;" : ""}</span><span><b>${esc(featureLabel(a.feature))}</b><small>${a.used ? `${esc(C.compact(a.events))} event(s) · last used ${esc(fmtTime(a.last_used_at, "unknown"))}` : "Not used yet"}</small></span></li>`).join("")}</ul>` : empty("No feature catalog returned.");
    } else $("c360Adoption").innerHTML = unavailableBox(analytics.status === 404 ? "Feature adoption needs per-customer analytics." : "Analytics failed to load.");

    // Timeline
    let events = [];
    if (an && Array.isArray(an.recent_events)) events = an.recent_events.map(e => ({ at: e.at, kind: e.kind, title: e.action, actor: e.actor, detail: e.detail }));
    else {
      (d.recent_logins || []).forEach(l => events.push({ at: l.created_at, kind: Number(l.status_code) >= 400 ? "auth-failed" : "auth", title: l.event_type || "login", actor: l.user_id, detail: [l.login_method, l.ip_address].filter(Boolean).join(" · ") }));
      (d.admin_events || []).forEach(e => events.push({ at: e.created_at, kind: "admin", title: e.action, actor: e.actor_id, detail: e.reason }));
      events.sort((a, b) => (Date.parse(b.at) || 0) - (Date.parse(a.at) || 0));
    }
    $("c360Timeline").innerHTML = events.length ? `<ol class="timeline">${events.slice(0, 25).map(e => `<li class="${/fail|deny|error/i.test(`${e.kind} ${e.title}`) ? "bad" : ""}"><time>${esc(fmtTime(e.at, ""))}</time><b>${esc(e.title || e.kind || "event")}</b><span>${esc([e.kind, e.actor].filter(Boolean).join(" · "))}</span>${e.detail ? `<small>${esc(typeof e.detail === "string" ? e.detail : JSON.stringify(e.detail))}</small>` : ""}</li>`).join("")}</ol>` : empty("No recorded activity for this organization.");

    // Onboarding
    const checks = d.onboarding_checklist?.checks || [];
    const passed = checks.filter(i => i.status === "pass").length;
    $("c360Onboarding").innerHTML = checks.length ? `<div class="adoptHead"><b>${fmt.format(passed)} of ${fmt.format(checks.length)}</b> steps complete <span class="meter"><i style="width:${Math.round((passed / checks.length) * 100)}%"></i></span></div><ul class="checklist">${checks.map(i => `<li class="${i.status === "pass" ? "done" : i.status === "warn" ? "warnItem" : ""}"><span class="tick" aria-hidden="true">${i.status === "pass" ? "&#10003;" : i.status === "warn" ? "!" : ""}</span><span><b>${esc(i.label)}</b><small>${esc(i.detail || "")}</small></span></li>`).join("")}</ul>` : empty("No onboarding checklist returned.");

    // Keys
    $("c360Keys").innerHTML = !keys.ok ? failRow(4, `API keys unavailable: ${keys.error}`, "c360") : (keys.data.items || []).length ? keys.data.items.map(k => `<tr><td><div class="cellStack"><b>${esc(k.name)}</b><span class="mono muted">${esc(k.prefix)}&hellip;</span></div></td><td>${tags(k.scopes)}</td><td class="mono">${esc(fmtTime(k.last_used_at, "Never"))}</td><td>${statusPill(k.status)}</td></tr>`).join("") : emptyRow(4, "No API keys for this organization.");

    // Sessions
    $("c360Sessions").innerHTML = !sessions.ok ? failRow(4, `Sessions unavailable: ${sessions.error}`, "c360") : !sessions.data.available ? emptyRow(4, "Session storage is not initialized on this deployment.") : (sessions.data.items || []).length ? sessions.data.items.map(x => `<tr><td><div class="cellStack"><b>${esc(x.email || x.user_id)}</b><span class="mono muted">${esc(x.session_id)}&hellip;</span></div></td><td>${esc(x.role || "—")}</td><td class="mono">${esc(fmtTime(x.created_at))}</td><td class="mono">${esc(fmtTime(x.expires_at))}</td></tr>`).join("") : emptyRow(4, "No active sessions.");

    // Flags
    const flagItems = flags.ok ? flags.data.items || [] : null;
    $("c360Flags").innerHTML = flagItems === null ? failBox(`Flags unavailable: ${flags.error}`, "c360") : flagItems.length ? `<ul class="flagList">${flagItems.map(f => `<li><span class="mono">${esc(f.flag_key)}</span>${statusPill(f.enabled ? "active" : "disabled")}<small>${esc(f.reason || "")}</small></li>`).join("")}</ul>` : empty("No overrides. Every flag uses the platform default.");

    // Notes
    $("c360Notes").innerHTML = kv([["Plan", c.plan_type || "starter"], ["Status", status], ["Lifecycle stage", c.lifecycle_stage], ["Renewal", c.renewal_at], ["Account owner", c.account_owner]]) + (c.internal_notes ? `<p class="notesText">${esc(c.internal_notes)}</p>` : empty("No internal notes yet."));
    A.applyRoleControls();
    window.AdminSupport?.render360(org).catch(() => {});
  }
  $("c360EditBtn")?.addEventListener("click", A.run(() => current.org && A.openCustomer(current.org, "drawerControls")));
  $("c360NotesBtn")?.addEventListener("click", A.run(() => current.org && A.openCustomer(current.org, "drawerControls")));
  $("c360FlagsBtn")?.addEventListener("click", A.run(() => current.org && A.openCustomer(current.org, "drawerFlags")));
  $("c360SuspendBtn")?.addEventListener("click", A.run(() => A.lifecycle(current.org, "suspend")));
  $("c360ResumeBtn")?.addEventListener("click", A.run(() => A.lifecycle(current.org, "resume")));
  $("c360ArchiveBtn")?.addEventListener("click", A.run(() => A.lifecycle(current.org, "archive")));
  const exportMenu = $("c360ExportMenu"), exportBtn = $("c360ExportBtn");
  const closeExport = (refocus) => { if (exportMenu.hidden) return; exportMenu.hidden = true; exportBtn.setAttribute("aria-expanded", "false"); if (refocus) exportBtn.focus(); };
  exportBtn?.addEventListener("click", () => { const open = exportMenu.hidden; exportMenu.hidden = !open; exportBtn.setAttribute("aria-expanded", String(open)); if (open) exportMenu.querySelector("button:not(:disabled)")?.focus(); });
  exportMenu?.addEventListener("keydown", event => {
    const items = [...exportMenu.querySelectorAll("button:not(:disabled)")];
    const i = items.indexOf(document.activeElement);
    if (event.key === "Escape") { event.preventDefault(); event.stopPropagation(); closeExport(true); }
    else if (event.key === "ArrowDown" || event.key === "ArrowUp") { event.preventDefault(); items[(i + (event.key === "ArrowDown" ? 1 : -1) + items.length) % items.length]?.focus(); }
  });
  document.addEventListener("pointerdown", event => { if (exportMenu && !exportMenu.hidden && !exportMenu.contains(event.target) && !exportBtn.contains(event.target)) closeExport(); });
  exportMenu?.addEventListener("click", A.run(async event => {
    const button = event.target.closest("[data-c360-export]");
    if (!button || !current.org) return;
    closeExport();
    const org = current.org;
    const kind = button.dataset.c360Export;
    A.setStatus(`Preparing ${kind === "gdpr" ? "GDPR export" : kind === "package" ? "audit package" : "tenant audit CSV"} for ${org}...`);
    if (kind === "gdpr") await A.download(`/platform/customers/${enc(org)}/export`, `pqc-gdpr-export-${org}.json`);
    else if (kind === "package") await A.download(`/platform/customers/${enc(org)}/audit-package`, `pqc-audit-package-${org}.zip`);
    else await A.download(`/platform/customers/${enc(org)}/audit-logs/export.csv`, `pqc-audit-${org}.csv`);
    A.setStatus(`Export for ${org} downloaded.`, "ok");
  }));

  // ---------- onboarding ----------
  async function loadOnboarding() {
    const org = $("onboardOrg").value;
    const body = $("onboardBody");
    if (!org) { body.innerHTML = empty("Choose an organization to evaluate its checklist."); return; }
    body.innerHTML = skeletonList(4);
    const res = await A.safeApi(`/platform/customers/${enc(org)}/onboarding-checklist`);
    if (!res.ok) { body.innerHTML = failBox(`Checklist unavailable: ${res.error}`, "onboarding"); return; }
    const checks = res.data.checks || res.data.onboarding_checklist?.checks || [];
    const passed = checks.filter(i => i.status === "pass").length;
    body.innerHTML = checks.length ? `<div class="adoptHead"><b>${fmt.format(passed)} of ${fmt.format(checks.length)}</b> steps complete <span class="meter"><i style="width:${Math.round((passed / checks.length) * 100)}%"></i></span> <a class="btn secondary small" href="#/customers/${esc(enc(org))}">Customer 360</a></div><ul class="checklist">${checks.map(i => `<li class="${i.status === "pass" ? "done" : i.status === "warn" ? "warnItem" : ""}"><span class="tick" aria-hidden="true">${i.status === "pass" ? "&#10003;" : i.status === "warn" ? "!" : ""}</span><span><b>${esc(i.label)}</b><small>${esc(i.detail || "")}</small></span></li>`).join("")}</ul>` : empty("No onboarding checklist returned.");
  }
  $("onboardOrg")?.addEventListener("change", A.run(loadOnboarding));

  // ---------- usage & adoption ----------
  let usageSeq = 0;
  async function loadUsage() {
    const seq = ++usageSeq;
    const range = getRange();
    $("usageBody").innerHTML = skeletonRows(6, 4);
    const res = await A.safeApi(`/platform/analytics/usage?range=${enc(range)}`);
    if (seq !== usageSeq) return;
    stamp("usageRefreshed");
    if (!res.ok) {
      const missing = res.status === 404;
      $("usageNotice").innerHTML = missing ? notice("warn", "Usage analytics are not available on this server yet.", "This page needs GET /platform/analytics/usage. Nothing is estimated in the meantime.") : failBox(`Usage could not be loaded: ${res.error}`, "usage");
      $("usageChart").innerHTML = unavailableBox(missing ? "Adoption needs the usage endpoint." : "Usage failed to load.");
      $("usageBody").innerHTML = emptyRow(6, missing ? NOT_AVAILABLE : "Unavailable.");
      return;
    }
    $("usageNotice").innerHTML = "";
    const d = res.data || {};
    const total = asNum(d.organizations_total);
    const features = (d.features || []).slice().sort((a, b) => asNum(b.organizations_using) - asNum(a.organizations_using));
    text("usageAdoptionCopy", total ? `Share of ${fmt.format(total)} organization(s) using each feature in the ${RANGES[range]}.` : `Organizations using each feature in the ${RANGES[range]}.`);
    C.bars($("usageChart"), { items: features.map(f => ({ label: f.label || f.key, value: asNum(f.organizations_using), detail: total ? `${Math.round((asNum(f.organizations_using) / total) * 100)}% of organizations` : "" })), max: total || undefined, format: v => (total ? `${fmt.format(v)} · ${Math.round((v / total) * 100)}%` : fmt.format(v)), emptyText: "No features reported." });
    $("usageBody").innerHTML = features.length ? features.map(f => {
      const d2 = isNum(f.delta_pct) ? Number(f.delta_pct) : null;
      const dir = d2 === null ? "flat" : d2 > 0.05 ? "up" : d2 < -0.05 ? "down" : "flat";
      const values = Array.isArray(f.series) ? f.series.map(p => (typeof p === "object" && p !== null ? p.value ?? p.events : p)) : [];
      return `<tr><td><div class="cellStack"><b>${esc(f.label || f.key)}</b><span class="mono muted">${esc(f.key)}</span></div></td><td class="num">${esc(fmt.format(asNum(f.organizations_using)))}${total ? ` <span class="muted">/ ${esc(fmt.format(total))}</span>` : ""}</td><td class="num">${esc(C.compact(f.events))}</td><td class="num"><span class="delta ${dir} ${dir === "up" ? "good" : dir === "down" ? "bad" : "neutral"}">${d2 === null ? "—" : `${d2 > 0 ? "+" : ""}${d2.toFixed(1)}%`}</span></td><td>${C.sparkline(values) || `<span class="muted">—</span>`}</td><td class="mono">${esc(fmtTime(f.last_used_at, "Never"))}</td></tr>`;
    }).join("") : emptyRow(6, "No features reported by this server.");
  }
  $("usageRefreshBtn")?.addEventListener("click", A.run(loadUsage));

  // ---------- background jobs ----------
  async function loadJobs() {
    const body = $("jobsBody");
    if (!body.querySelector("tr:not(.skeletonRow)")) body.innerHTML = skeletonRows(7, 4);
    const res = await A.safeApi("/platform/jobs");
    stamp("jobsRefreshed");
    if (!res.ok) { body.innerHTML = res.status === 404 ? `<tr><td colspan="7">${unavailableBox("Job tracking needs GET /platform/jobs.")}</td></tr>` : failRow(7, `Jobs could not be loaded: ${res.error}`, "jobs"); return; }
    const jobs = res.data.jobs || [];
    body.innerHTML = jobs.length ? jobs.map(j => `<tr data-record-id="${esc(j.key)}"><td><div class="cellStack"><b>${esc(j.label || j.key)}</b><span class="mono muted">${esc(j.key)}</span>${j.detail ? `<span class="muted">${esc(j.detail)}</span>` : ""}</div></td><td>${esc(j.kind || "—")}</td><td>${statusPill(j.status || "unknown")}</td><td class="mono">${esc(fmtTime(j.last_run_at, "Never"))}</td><td class="mono">${esc(fmtTime(j.next_run_at, "Not scheduled"))}</td><td class="num">${isNum(j.runs_24h) ? esc(fmt.format(Number(j.runs_24h))) : "—"}</td><td>${j.last_error ? `<details class="detailsBlock"><summary class="warnText">${esc(String(j.last_error).slice(0, 60))}${String(j.last_error).length > 60 ? "&hellip;" : ""}</summary><pre class="codeBlock">${esc(j.last_error)}</pre></details>` : `<span class="muted">None</span>`}</td></tr>`).join("") : emptyRow(7, "No background jobs are registered on this server.");
  }
  $("jobsRefreshBtn")?.addEventListener("click", A.run(loadJobs));

  // ---------- notifications page ----------
  function renderNotificationsPage() {
    const host = $("notificationsBody");
    const notes = S.notifications;
    text("notesRefreshed", notes.loadedAt ? `Refreshed ${new Date(notes.loadedAt).toLocaleTimeString()}` : "");
    if (notes.status === "loading" && !notes.data) { host.innerHTML = skeletonList(4); return; }
    if (notes.status === "unavailable") { host.innerHTML = unavailableBox("Notifications need GET /platform/notifications."); return; }
    if (notes.status === "error") { host.innerHTML = failBox(`Notifications could not be loaded: ${notes.error}`, "notifications"); return; }
    const items = notes.data?.items || [];
    const counts = notes.data?.counts || {};
    if (!items.length) { host.innerHTML = `<div class="emptyState"><b>All clear</b><span>No open notifications.</span></div>`; return; }
    host.innerHTML = `<div class="noteCounts">${["critical", "warn", "info"].map(s => `<span class="sevCount ${s}"><span class="sev ${s}"></span>${esc(s)} <b>${esc(fmt.format(asNum(counts[s] ?? items.filter(i => S.severity(i) === s).length)))}</b></span>`).join("")}</div>` +
      ["critical", "warn", "info"].map(sev => {
        const list = items.filter(i => S.severity(i) === sev);
        if (!list.length) return "";
        return `<h3 class="groupTitle">${sev === "critical" ? "Critical" : sev === "warn" ? "Warning" : "Info"}</h3><ul class="attention full">${list.map(item => `<li class="${S.isRead(item.id) ? "read" : ""}"><span class="sev ${sev}" aria-hidden="true"></span><a href="${esc(S.routeHref(item.route) || "#/notifications")}"><b>${esc(item.title || item.kind)}</b>${item.detail ? `<small>${esc(item.detail)}</small>` : ""}</a><time title="${esc(fmtTime(item.created_at, ""))}">${esc([item.kind, S.relTime(item.created_at)].filter(Boolean).join(" · "))}</time></li>`).join("")}</ul>`;
      }).join("");
  }
  $("notesRefreshBtn")?.addEventListener("click", () => S.loadNotifications());
  $("notesMarkAllBtn")?.addEventListener("click", () => S.markAllRead());

  // ---------- feature flags page ----------
  async function loadFlagsCatalog() {
    const body = $("flagsCatalogBody");
    const res = await A.safeApi("/platform/feature-flags/catalog");
    if (!res.ok) { body.innerHTML = failBox(`Flag catalog unavailable: ${res.error}`, "flags"); return; }
    const items = res.data.items || [];
    text("flagsSemantics", res.data.semantics || "Known flags and how an override behaves.");
    $("flagCatalogPage").innerHTML = items.map(f => `<option value="${esc(f.flag_key)}">${esc(f.label)}</option>`).join("");
    body.innerHTML = items.length ? `<ul class="flagList">${items.map(f => `<li><span class="mono">${esc(f.flag_key)}</span><b>${esc(f.label || "")}</b>${f.default !== undefined ? statusPill(f.default ? "active" : "off") : ""}<small>${esc(f.description || f.detail || "")}</small></li>`).join("")}</ul>` : empty("No flags in the catalog.");
    if ($("flagsOrg").value) await loadOrgFlags();
  }
  async function loadOrgFlags() {
    const org = $("flagsOrg").value;
    const body = $("flagsBody");
    if (!org) { body.innerHTML = empty("Choose an organization to see its overrides."); return; }
    body.innerHTML = skeletonList(3);
    const res = await A.safeApi(`/platform/customers/${enc(org)}/feature-flags`);
    if (!res.ok) { body.innerHTML = failBox(`Overrides unavailable: ${res.error}`, "flags"); return; }
    const items = res.data.items || [];
    body.innerHTML = items.length ? items.map(i => `<div class="event"><b>${esc(i.flag_key)} ${statusPill(i.enabled ? "active" : "disabled")}</b><span>${esc(i.reason || "")}</span><span class="mono">${esc(fmtTime(i.updated_at, ""))}</span><div class="row"><button class="btn danger small" type="button" data-write data-page-flag-delete="${esc(i.flag_key)}">Remove override</button></div></div>`).join("") : empty("No overrides for this organization.");
    A.applyRoleControls();
  }
  $("flagsOrg")?.addEventListener("change", A.run(loadOrgFlags));
  $("flagsCatalogBtn")?.addEventListener("click", A.run(loadFlagsCatalog));
  $("flagsForm")?.addEventListener("submit", A.run(async () => {
    const org = $("flagsOrg").value, flagKey = $("flagsKey").value.trim();
    if (!org || !flagKey) { A.note("flagsStatus", "Choose an organization and a flag key.", "bad"); return; }
    await A.api(`/platform/customers/${enc(org)}/feature-flags`, { method: "PUT", json: { flag_key: flagKey, enabled: $("flagsEnabled").value === "true", reason: $("flagsReason").value || "" } });
    $("flagsReason").value = "";
    A.note("flagsStatus", `${flagKey} saved for ${org}.`, "ok");
    await loadOrgFlags();
  }));
  $("flagsBody")?.addEventListener("click", A.run(async event => {
    const button = event.target.closest("[data-page-flag-delete]");
    if (!button) return;
    const org = $("flagsOrg").value, flag = button.dataset.pageFlagDelete;
    const values = await A.openDialog({ title: `Remove the ${flag} override`, body: "The feature falls back to the platform default for this customer.", reason: true, submitLabel: "Remove override", danger: true });
    if (!values) return;
    await A.api(`/platform/customers/${enc(org)}/feature-flags/${enc(flag)}?reason=${enc(values.reason)}`, { method: "DELETE" });
    A.setStatus(`${flag} override removed for ${org}.`, "ok");
    await loadOrgFlags();
  }));

  // ---------- operators ----------
  function renderWhoami() {
    const who = A.identity();
    $("whoamiBody").innerHTML = who ? kv([["Operator", who.operator], ["Active role", A.role()], ["Role bound to key", who.role_bound ? "yes" : "no (shared key)"], ["Role ceiling", who.ceiling_role], ["Allowed roles", (who.allowed_roles || []).join(", ")], ["Write access", A.canWrite() ? "yes" : "read-only"]]) : empty("Identity unavailable: /platform/whoami did not answer.");
  }

  // Nothing renders until a credential connects; the sign-in screen owns the page until then.
  window.AdminApp = { go, render, current: () => current, loadDashboard, load360 };
  if (!location.hash) history.replaceState(null, "", "#/dashboard");
  else { const parsed = parseHash(); if (parsed.legacy) history.replaceState(null, "", `#/${parsed.legacy}`); }
})();
