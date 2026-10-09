(() => {
  "use strict";
  /* ==========================================================================
     Operator console shell, shared by the portal and Traffic Lens.

     - Grouped dropdown navigation built from one information architecture.
       Disclosure buttons (aria-expanded), arrow-key movement inside and across
       menus, Escape, outside click, and hover intent on fine pointers. Below
       1100px the same markup becomes an off-canvas drawer of accordions.
     - Ctrl/Cmd+K command palette: pages and actions matched locally, records
       from GET /platform/search (debounced, two characters or more).
     - Notifications bell over GET /platform/notifications, with read state kept
       in sessionStorage for this tab.
     - Operator menu popover (portal only; its markup lives in index.html).

     Every endpoint may be missing on an older server: a 404 renders an honest
     "not available on this server yet" state, never placeholder numbers.
     ========================================================================== */

  const bar = document.querySelector("[data-shell-bar]");
  if (!bar) return;
  const inPortal = document.body.classList.contains("admin-console");
  const PORTAL = "/vendor-admin/";
  const href = route => (inPortal ? `#/${route}` : `${PORTAL}#/${route}`);
  const esc = value => String(value ?? "").replace(/[&<>"']/g, ch => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[ch]));
  const READ_KEY = "pqc_admin_read_notifications";

  const IA = [
    { id: "dashboard", label: "Dashboard", route: "dashboard", desc: "KPIs, trends, and what needs attention" },
    { id: "customers", label: "Customers", items: [
      { route: "customers", label: "Organizations", desc: "Every tenant with status, plan, risk and activity", count: "organizations" },
      { route: "customer-360", label: "Customer 360", desc: "One organization: activity, members, keys, lifecycle" },
      { route: "users", label: "Users", desc: "Accounts, role assignments and deactivation" },
      { route: "trials", label: "Trial requests", desc: "Strangers asking for an account, and the decision on each", count: "pendingTrials" },
      { route: "invitations", label: "Invitations", desc: "Single-use, expiring invitations to a tenant" },
      { route: "support-sessions", label: "Support sessions", desc: "Read-only view-as-customer sessions and revocation" },
      { route: "onboarding", label: "Onboarding", desc: "Activation risk and per-tenant checklists", count: "atRisk" },
      { route: "feedback", label: "Customer feedback", desc: "Bugs, ideas and questions to triage", count: "openFeedback" }
    ] },
    { id: "product", label: "Product", items: [
      { route: "usage", label: "Usage & adoption", desc: "Which features organizations actually use" },
      { route: "flags", label: "Feature flags", desc: "Catalog and per-organization overrides" },
      { route: "announcements", label: "Announcements", desc: "Banners shown in the customer console" }
    ] },
    { id: "access", label: "Access", items: [
      { route: "api-keys", label: "API keys", desc: "Issue, rotate and revoke organization keys", count: "activeKeys" },
      { route: "sessions", label: "Sessions", desc: "Active sign-in sessions and revocation", count: "activeSessions" },
      { route: "operators", label: "Operators & roles", desc: "Named operator credentials and your role" },
      { route: "rate-limits", label: "Rate limits", desc: "Per-organization overrides and 429 pressure" }
    ] },
    { id: "operations", label: "Operations", items: [
      { route: "health", label: "Service health", desc: "Dependencies, observability and log storage" },
      { route: "traffic", label: "Traffic Lens", desc: "Request metadata by source IP and route", url: "/vendor-admin/traffic.html" },
      { route: "incidents", label: "Incidents & abuse", desc: "Errors, slow requests and rate-limit pressure", count: "incidents" },
      { route: "jobs", label: "Background jobs", desc: "Scheduled work, last and next runs, failures" },
      { route: "alert-routing", label: "Alert routing", desc: "Slack, email, PagerDuty and webhook alerts" },
      { route: "maintenance", label: "Maintenance mode", desc: "Pause customer writes with a message", count: "maintenance" },
      { route: "autopatch", label: "Autopatch", desc: "Governed fix intake and draft PRs", count: "pendingAutopatches" }
    ] },
    { id: "security", label: "Security", items: [
      { route: "launch", label: "Launch readiness", desc: "Go-live gate and production readiness checks" },
      { route: "security-truth", label: "Security truth", desc: "External findings and write-path guardrails" },
      { route: "isolation", label: "Tenant isolation & RLS", desc: "Cross-tenant probe and row-level security plan" },
      { route: "audit", label: "Audit log", desc: "Tenant audit, admin events, authentication" },
      { route: "data", label: "Data & retention", desc: "Retention runs, state coverage, exports" }
    ] },
    { id: "help", label: "Help", items: [
      { route: "guide", label: "Administrator guide", desc: "Operating procedures for this platform", url: "/enterprise-admin", external: true },
      { route: "support", label: "Support", desc: "How to reach us and the incident process", url: "/support", external: true },
      { route: "website", label: "Public website", desc: "The public Airlock site", url: "/", external: true }
    ] }
  ];
  const EXTRA_PAGES = [{ route: "notifications", label: "Notifications", desc: "Everything the platform raised for operators", group: "Operations" }];

  function allPages() {
    const pages = [];
    IA.forEach(group => {
      if (!group.items) pages.push({ route: group.route, label: group.label, desc: group.desc, group: "", top: group.id });
      else group.items.forEach(item => pages.push({ ...item, group: group.label, top: group.id }));
    });
    return pages.concat(EXTRA_PAGES.map(p => ({ ...p, top: "operations" })));
  }
  const itemHref = item => item.url || href(item.route);

  // ---------- markup ----------
  const nav = bar.querySelector("[data-shell-nav]");
  nav.innerHTML = IA.map(group => {
    if (!group.items) return `<a class="sh-top" href="${esc(href(group.route))}" data-top="${esc(group.id)}" data-route="${esc(group.route)}">${esc(group.label)}</a>`;
    return `<div class="sh-group" data-group="${esc(group.id)}"><button class="sh-top" type="button" id="shTop-${esc(group.id)}" data-top="${esc(group.id)}" aria-expanded="false" aria-controls="shDrop-${esc(group.id)}">${esc(group.label)}<span class="sh-caret" aria-hidden="true"></span></button>
      <div class="sh-drop" id="shDrop-${esc(group.id)}" hidden><div class="sh-dropHead" aria-hidden="true">${esc(group.label)}</div>${group.items.map(item => `<a class="sh-link" href="${esc(itemHref(item))}" data-route="${esc(item.route)}"${item.external ? ` target="_blank" rel="noopener"` : ""}><b>${esc(item.label)}${item.url && !item.external ? "" : item.external ? ` <span class="sh-ext" aria-hidden="true">&#8599;</span>` : ""}</b><small>${esc(item.desc)}</small>${item.count ? `<span class="sh-count" data-count="${esc(item.count)}" hidden></span>` : ""}</a>`).join("")}</div></div>`;
  }).join("");
  const tops = () => [...nav.querySelectorAll(".sh-top")];
  const groups = [...nav.querySelectorAll(".sh-group")];
  const drawerMedia = matchMedia("(max-width: 1100px)");
  const finePointer = matchMedia("(hover: hover) and (pointer: fine)");
  const isDrawer = () => drawerMedia.matches;

  // ---------- dropdown menus ----------
  let openGroup = null, hoverTimer = 0, hoverOpened = null;
  function menuFor(group) { return { button: group.querySelector(".sh-top"), drop: group.querySelector(".sh-drop"), links: [...group.querySelectorAll(".sh-link")] }; }
  function openMenu(group, focus = "") {
    if (openGroup && openGroup !== group && !isDrawer()) closeMenu(openGroup);
    const { button, drop, links } = menuFor(group);
    button.setAttribute("aria-expanded", "true");
    drop.hidden = false;
    openGroup = group;
    if (focus === "first") links[0]?.focus();
    if (focus === "last") links[links.length - 1]?.focus();
  }
  function closeMenu(group, refocus = false) {
    if (!group) return;
    const { button, drop } = menuFor(group);
    button.setAttribute("aria-expanded", "false");
    drop.hidden = true;
    if (openGroup === group) openGroup = null;
    if (refocus) button.focus();
  }
  function closeMenus() { groups.forEach(g => closeMenu(g)); }
  function moveTop(from, delta, openIt) {
    const list = tops();
    const i = list.indexOf(from);
    const next = list[(i + delta + list.length) % list.length];
    const group = next.closest(".sh-group");
    if (openIt && group) { openMenu(group, "first"); return; }
    if (!isDrawer()) closeMenus();
    next.focus();
  }
  nav.addEventListener("click", event => {
    const button = event.target.closest("button.sh-top");
    if (button) {
      const group = button.closest(".sh-group");
      clearTimeout(hoverTimer);
      // A click on a menu that hover just opened keeps it open instead of toggling it shut.
      if (hoverOpened === group) { hoverOpened = null; openMenu(group); return; }
      button.getAttribute("aria-expanded") === "true" ? closeMenu(group) : openMenu(group);
      return;
    }
    const link = event.target.closest("a");
    if (link) { if (!isDrawer()) closeMenus(); else closeDrawer(); }
  });
  nav.addEventListener("keydown", event => {
    const top = event.target.closest(".sh-top");
    const link = event.target.closest(".sh-link");
    const horizontal = !isDrawer();
    if (!horizontal && event.key === "Escape") { event.preventDefault(); event.stopPropagation(); closeDrawer(true); return; }
    if (top && !link) {
      const group = top.closest(".sh-group");
      if (event.key === "ArrowDown" && group) { event.preventDefault(); openMenu(group, "first"); }
      else if (event.key === "ArrowUp" && group) { event.preventDefault(); openMenu(group, "last"); }
      else if (horizontal && (event.key === "ArrowRight" || event.key === "ArrowLeft")) { event.preventDefault(); moveTop(top, event.key === "ArrowRight" ? 1 : -1, !!openGroup); }
      else if (event.key === "Escape" && group && top.getAttribute("aria-expanded") === "true") { event.preventDefault(); event.stopPropagation(); closeMenu(group, true); }
      else if (event.key === "Home") { event.preventDefault(); tops()[0].focus(); }
      else if (event.key === "End") { event.preventDefault(); tops()[tops().length - 1].focus(); }
      return;
    }
    if (!link) return;
    const group = link.closest(".sh-group");
    const { button, links } = menuFor(group);
    const i = links.indexOf(link);
    if (event.key === "ArrowDown") { event.preventDefault(); links[(i + 1) % links.length].focus(); }
    else if (event.key === "ArrowUp") { event.preventDefault(); links[(i - 1 + links.length) % links.length].focus(); }
    else if (event.key === "Home") { event.preventDefault(); links[0].focus(); }
    else if (event.key === "End") { event.preventDefault(); links[links.length - 1].focus(); }
    else if (event.key === "Escape") { event.preventDefault(); event.stopPropagation(); closeMenu(group, true); }
    else if (horizontal && (event.key === "ArrowRight" || event.key === "ArrowLeft")) { event.preventDefault(); closeMenu(group); moveTop(button, event.key === "ArrowRight" ? 1 : -1, true); }
    else if (event.key === " ") { event.preventDefault(); link.click(); }
  });
  nav.addEventListener("focusout", event => {
    if (isDrawer() || !openGroup) return;
    const next = event.relatedTarget;
    if (!next || !openGroup.contains(next)) {
      // Focus left the open menu for somewhere else (Tab): close it, unless it moved to another top button.
      if (!next || !nav.contains(next)) closeMenus();
    }
  });
  groups.forEach(group => {
    group.addEventListener("pointerenter", event => {
      if (event.pointerType !== "mouse" || isDrawer() || !finePointer.matches) return;
      clearTimeout(hoverTimer);
      if (openGroup === group) return;
      hoverTimer = setTimeout(() => { if (openGroup !== group) { openMenu(group); hoverOpened = group; setTimeout(() => { if (hoverOpened === group) hoverOpened = null; }, 700); } }, openGroup ? 0 : 130);
    });
    group.addEventListener("pointerleave", event => {
      if (event.pointerType !== "mouse" || isDrawer() || !finePointer.matches) return;
      clearTimeout(hoverTimer);
      hoverTimer = setTimeout(() => { if (openGroup === group && !group.contains(document.activeElement)) closeMenu(group); }, 260);
    });
  });

  // ---------- drawer ----------
  const burger = bar.querySelector("[data-shell-burger]");
  const backdrop = document.createElement("div");
  backdrop.className = "sh-drawerBackdrop";
  backdrop.hidden = true;
  // Inside the bar so it shares the bar's stacking context and sits just under the drawer.
  bar.prepend(backdrop);
  function openDrawer() {
    bar.classList.add("sh-drawerOpen");
    burger?.setAttribute("aria-expanded", "true");
    backdrop.hidden = false;
    const current = nav.querySelector(".sh-current") || tops()[0];
    const group = current?.closest(".sh-group");
    if (group) openMenu(group);
    (current || tops()[0])?.focus();
  }
  function closeDrawer(refocus = false) {
    if (!bar.classList.contains("sh-drawerOpen")) return;
    bar.classList.remove("sh-drawerOpen");
    burger?.setAttribute("aria-expanded", "false");
    backdrop.hidden = true;
    if (refocus) burger?.focus();
  }
  burger?.addEventListener("click", () => (bar.classList.contains("sh-drawerOpen") ? closeDrawer(true) : openDrawer()));
  backdrop.addEventListener("click", () => closeDrawer(true));
  drawerMedia.addEventListener("change", () => { closeDrawer(); closeMenus(); });

  // ---------- popovers (bell, operator menu) ----------
  const popovers = [];
  function popover(button, panel, onOpen) {
    if (!button || !panel) return null;
    const pop = {
      button, panel,
      open() { popovers.forEach(p => p !== pop && p.close()); closeMenus(); panel.hidden = false; button.setAttribute("aria-expanded", "true"); onOpen?.(); },
      close(refocus = false) { if (panel.hidden) return; panel.hidden = true; button.setAttribute("aria-expanded", "false"); if (refocus) button.focus(); },
      isOpen: () => !panel.hidden
    };
    button.addEventListener("click", () => (pop.isOpen() ? pop.close() : pop.open()));
    panel.addEventListener("keydown", event => {
      if (event.key === "Escape") { event.preventDefault(); event.stopPropagation(); pop.close(true); return; }
      if (event.key !== "ArrowDown" && event.key !== "ArrowUp") return;
      const items = [...panel.querySelectorAll("a[href], button:not(:disabled), select:not(:disabled)")].filter(el => el.getClientRects().length);
      if (!items.length || event.target.tagName === "SELECT") return;
      event.preventDefault();
      const i = items.indexOf(document.activeElement);
      items[(i + (event.key === "ArrowDown" ? 1 : -1) + items.length) % items.length].focus();
    });
    panel.addEventListener("click", event => { if (event.target.closest("a[href]")) pop.close(); });
    popovers.push(pop);
    return pop;
  }
  const operatorPop = popover(bar.querySelector(".sh-opBtn"), bar.querySelector(".sh-opPanel"));

  document.addEventListener("pointerdown", event => {
    if (openGroup && !isDrawer() && !openGroup.contains(event.target)) closeMenus();
    popovers.forEach(p => { if (p.isOpen() && !p.panel.contains(event.target) && !p.button.contains(event.target)) p.close(); });
  });
  document.addEventListener("keydown", event => {
    if (event.key !== "Escape" || event.defaultPrevented) return;
    if (window.AirlockAdmin?.dialogOpen() || window.AirlockAdmin?.drawerOpen()) return;
    if (palette && !palette.hidden) return;
    if (openGroup && !isDrawer()) { closeMenu(openGroup, true); return; }
    const open = popovers.find(p => p.isOpen());
    if (open) { open.close(true); return; }
    if (bar.classList.contains("sh-drawerOpen")) closeDrawer(true);
  });

  // ---------- current section & counts ----------
  function setCurrent(route) {
    const base = String(route || "").split("?")[0];
    const page = /^customers\/.+/.test(base) ? "customer-360" : base;
    nav.querySelectorAll("[aria-current]").forEach(el => el.removeAttribute("aria-current"));
    nav.querySelectorAll(".sh-current").forEach(el => el.classList.remove("sh-current"));
    const link = nav.querySelector(`.sh-link[data-route="${CSS.escape(page)}"]`);
    if (link) { link.setAttribute("aria-current", "page"); link.closest(".sh-group")?.querySelector(".sh-top")?.classList.add("sh-current"); }
    const top = nav.querySelector(`a.sh-top[data-route="${CSS.escape(page)}"]`);
    if (top) { top.setAttribute("aria-current", "page"); top.classList.add("sh-current"); }
    if (page === "notifications") nav.querySelector('[data-top="operations"]')?.classList.add("sh-current");
  }
  // counts: { key: number|null } ; kinds: { key: "warn"|"bad" }
  function setCounts(counts = {}, kinds = {}) {
    Object.entries(counts).forEach(([key, value]) => {
      nav.querySelectorAll(`[data-count="${CSS.escape(key)}"]`).forEach(badge => {
        const show = value !== null && value !== undefined && value !== "" && value !== 0;
        badge.hidden = !show;
        badge.textContent = show ? String(value) : "";
        badge.className = `sh-count${kinds[key] ? ` ${kinds[key]}` : ""}`;
      });
    });
  }

  // ---------- API access ----------
  // The portal passes requests through its own client (session versioning, role header).
  // Traffic Lens exposes window.TrafficLens (platform key or operator session cookie).
  async function request(path) {
    if (window.AirlockAdmin) {
      if (!window.AirlockAdmin.isConnected()) { const e = new Error("Not connected."); e.status = 0; throw e; }
      return window.AirlockAdmin.api(path);
    }
    if (window.TrafficLens) {
      if (!window.TrafficLens.connected()) { const e = new Error("Enter the platform key first."); e.status = 0; throw e; }
      return window.TrafficLens.api(path);
    }
    const key = (document.getElementById("platformKey")?.value || "").trim();
    if (!key) { const e = new Error("Enter the platform key first."); e.status = 0; throw e; }
    const res = await fetch(path, { cache: "no-store", signal: AbortSignal.timeout(20000), headers: { "x-platform-key": key, "x-platform-admin-role": document.getElementById("platformRole")?.value || "auditor" } });
    let data = {};
    try { data = await res.json(); } catch { data = {}; }
    if (!res.ok) { const e = new Error(typeof data.detail === "string" ? data.detail : `${res.status} ${res.statusText}`); e.status = res.status; throw e; }
    return data;
  }
  const canRequest = () => (window.AirlockAdmin ? window.AirlockAdmin.isConnected() : window.TrafficLens ? window.TrafficLens.connected() : !!(document.getElementById("platformKey")?.value || "").trim());
  const relTime = value => {
    const d = window.AdminCharts?.parseTime(value) || (value ? new Date(value) : null);
    if (!d || Number.isNaN(d.getTime())) return "";
    const s = Math.round((Date.now() - d.getTime()) / 1000);
    if (s < 60) return "just now";
    if (s < 3600) return `${Math.round(s / 60)} min ago`;
    if (s < 86400) return `${Math.round(s / 3600)} h ago`;
    return d.toLocaleDateString([], { month: "short", day: "numeric" });
  };
  const routeHref = route => {
    const r = String(route || "").trim();
    if (!r) return "";
    if (/^#\//.test(r)) return inPortal ? r : PORTAL + r;
    if (/^\/[^/]/.test(r)) return r;
    return "";
  };

  // ---------- notifications ----------
  const bellHost = bar.querySelector("[data-shell-bell]");
  const notes = { status: "idle", data: null, error: "", loadedAt: 0 };
  let readIds = new Set();
  try { readIds = new Set(JSON.parse(sessionStorage.getItem(READ_KEY) || "[]")); } catch { readIds = new Set(); }
  const saveRead = () => { try { sessionStorage.setItem(READ_KEY, JSON.stringify([...readIds].slice(-500))); } catch { /* optional */ } };
  let bellPop = null;
  if (bellHost) {
    bellHost.innerHTML = `<button class="sh-icon" type="button" id="shBellBtn" aria-expanded="false" aria-controls="shBellPanel" aria-label="Notifications"><svg width="17" height="17" viewBox="0 0 16 16" aria-hidden="true"><path d="M8 1.8a4.2 4.2 0 0 0-4.2 4.2v2.6L2.5 11h11l-1.3-2.4V6A4.2 4.2 0 0 0 8 1.8z" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linejoin="round"/><path d="M6.3 12.8a1.8 1.8 0 0 0 3.4 0" fill="none" stroke="currentColor" stroke-width="1.3"/></svg><span class="sh-badge" hidden></span></button>
      <div class="sh-panel" id="shBellPanel" hidden><div class="sh-panelHead"><b>Notifications</b><button class="sh-textBtn" type="button" data-mark-read>Mark all read</button></div><div class="sh-panelBody" data-bell-body></div><div class="sh-panelFoot"><a href="${esc(href("notifications"))}">View all notifications</a><span data-bell-time></span></div></div>`;
    bellPop = popover(bellHost.querySelector(".sh-icon"), bellHost.querySelector(".sh-panel"), () => {
      if (notes.status !== "loading" && Date.now() - notes.loadedAt > 20000) loadNotifications();
      else renderBell();
    });
    bellHost.querySelector("[data-mark-read]").addEventListener("click", () => markAllRead());
  }
  const SEVERITIES = [["critical", "Critical"], ["warn", "Warning"], ["info", "Info"]];
  const sevOf = item => { const s = String(item.severity || "info").toLowerCase(); return s === "critical" || s === "high" || s === "bad" ? "critical" : s === "warn" || s === "warning" || s === "medium" ? "warn" : "info"; };
  function unread() { return (notes.data?.items || []).filter(item => !readIds.has(String(item.id))); }
  function renderBell() {
    if (!bellHost) return;
    const badge = bellHost.querySelector(".sh-badge");
    const button = bellHost.querySelector(".sh-icon");
    const body = bellHost.querySelector("[data-bell-body]");
    const markBtn = bellHost.querySelector("[data-mark-read]");
    const fresh = unread();
    const crit = fresh.some(i => sevOf(i) === "critical");
    badge.hidden = !fresh.length;
    badge.textContent = fresh.length > 99 ? "99+" : String(fresh.length);
    badge.className = `sh-badge${crit ? " crit" : fresh.some(i => sevOf(i) === "warn") ? " warn" : ""}`;
    button.setAttribute("aria-label", fresh.length ? `Notifications, ${fresh.length} unread${crit ? ", including critical" : ""}` : "Notifications");
    markBtn.disabled = !fresh.length;
    const time = bellHost.querySelector("[data-bell-time]");
    time.textContent = notes.loadedAt ? `Updated ${new Date(notes.loadedAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}` : "";
    if (notes.status === "loading" && !notes.data) { body.innerHTML = `<div class="sh-empty">Loading notifications&hellip;</div>`; return; }
    if (notes.status === "unavailable") { body.innerHTML = `<div class="sh-empty">Notifications are not available on this server yet.</div>`; return; }
    if (notes.status === "signed-out") { body.innerHTML = `<div class="sh-empty">Connect with a platform key to see notifications.</div>`; return; }
    if (notes.status === "error") { body.innerHTML = `<div class="sh-empty">Notifications could not be loaded: ${esc(notes.error)} <button class="sh-textBtn" type="button" data-bell-retry>Retry</button></div>`; body.querySelector("[data-bell-retry]").addEventListener("click", () => loadNotifications()); return; }
    const items = notes.data?.items || [];
    if (!items.length) { body.innerHTML = `<div class="sh-empty">Nothing needs your attention.</div>`; return; }
    body.innerHTML = SEVERITIES.map(([sev, label]) => {
      const list = items.filter(i => sevOf(i) === sev);
      if (!list.length) return "";
      return `<div class="sh-sev ${sev}">${label} · ${list.length}</div>` + list.slice(0, 8).map(item => {
        const target = routeHref(item.route) || href("notifications");
        return `<a class="sh-note${readIds.has(String(item.id)) ? "" : " unread"}" href="${esc(target)}" data-note-id="${esc(item.id)}"><b>${esc(item.title || item.kind || "Notification")}</b>${item.detail ? `<span>${esc(item.detail)}</span>` : ""}<time>${esc([item.kind, relTime(item.created_at)].filter(Boolean).join(" · "))}</time></a>`;
      }).join("");
    }).join("");
    body.querySelectorAll("[data-note-id]").forEach(link => link.addEventListener("click", () => { readIds.add(link.dataset.noteId); saveRead(); renderBell(); emit(); }));
  }
  function emit() { document.dispatchEvent(new CustomEvent("shell:notifications", { detail: notes })); }
  let notesSeq = 0;
  async function loadNotifications() {
    if (!canRequest()) { notes.status = "signed-out"; renderBell(); emit(); return notes; }
    const seq = ++notesSeq;
    notes.status = "loading";
    renderBell();
    try {
      const data = await request("/platform/notifications");
      if (seq !== notesSeq) return notes;
      notes.data = { counts: data.counts || {}, items: Array.isArray(data.items) ? data.items : [] };
      notes.status = "ok"; notes.error = "";
    } catch (err) {
      if (seq !== notesSeq) return notes;
      if (err.status === 404) { notes.status = "unavailable"; notes.data = null; }
      else if (err.status === 0) notes.status = "signed-out";
      else { notes.status = "error"; notes.error = err.message || String(err); }
    }
    notes.loadedAt = Date.now();
    renderBell();
    emit();
    return notes;
  }
  function markAllRead() {
    (notes.data?.items || []).forEach(item => readIds.add(String(item.id)));
    saveRead();
    renderBell();
    emit();
  }
  // Auto-refresh every 60s while the tab is visible; a hidden tab catches up when shown.
  setInterval(() => { if (!document.hidden && canRequest() && notes.status !== "unavailable") loadNotifications(); }, 60000);
  document.addEventListener("visibilitychange", () => { if (!document.hidden && canRequest() && notes.status !== "unavailable" && Date.now() - notes.loadedAt > 60000) loadNotifications(); });

  // ---------- command palette ----------
  const searchButton = bar.querySelector("[data-shell-search]");
  const palette = document.createElement("div");
  palette.className = "sh-palette";
  palette.hidden = true;
  palette.innerHTML = `<div class="sh-scrim" data-pal-close></div><div class="sh-palBox" role="dialog" aria-modal="true" aria-label="Search and jump">
    <div class="sh-palInput"><svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true"><circle cx="7" cy="7" r="5" fill="none" stroke="#8A94A6" stroke-width="1.5"/><path d="M11 11l3.5 3.5" stroke="#8A94A6" stroke-width="1.5"/></svg><input type="text" role="combobox" aria-expanded="true" aria-controls="shPalList" aria-autocomplete="list" autocomplete="off" spellcheck="false" placeholder="Search pages, actions, organizations, users&hellip;" aria-label="Search"><kbd class="sh-kbd">Esc</kbd></div>
    <ul class="sh-palList" id="shPalList" role="listbox" aria-label="Results"></ul>
    <div class="sh-palStatus" aria-live="polite"></div>
    <div class="sh-palFoot"><span>&uarr; &darr; move</span><span>Enter open</span><span>Esc close</span></div></div>`;
  document.body.appendChild(palette);
  const palInput = palette.querySelector("input");
  const palList = palette.querySelector(".sh-palList");
  const palStatus = palette.querySelector(".sh-palStatus");
  let palItems = [], palActive = 0, palReturn = null, palTimer = 0, palSeq = 0, remote = { q: "", results: [], status: "" };

  const ACTIONS = [
    { label: "Create customer", desc: "Open the new customer form", route: "customers?create=1", keywords: "new organization tenant add" },
    { label: "New announcement", desc: "Publish a banner to customers", route: "announcements?new=1", keywords: "banner notice" },
    { label: "Turn maintenance on or off", desc: "Pause customer writes", route: "maintenance", keywords: "maintenance downtime" },
    { label: "Check launch gate", desc: "Evaluate the go-live gate now", route: "launch", keywords: "go live readiness gate" },
    { label: "Verify tenant isolation", desc: "Open the cross-tenant probe", route: "isolation", keywords: "rls probe" },
    { label: "Create API key", desc: "Issue a key for an organization", route: "api-keys", keywords: "token credential" },
    { label: "Revoke access", desc: "Sign out a user or organization", route: "sessions", keywords: "logout session revoke" },
    { label: "Search admin audit", desc: "Every platform administration change", route: "audit", keywords: "events log history" },
    { label: "Refresh data", desc: "Reload the platform snapshot", run: () => window.AirlockAdmin?.loadPortal().catch(window.AirlockAdmin.reportLoadError), portalOnly: true, keywords: "reload" },
    { label: "Sign out", desc: "Forget the credential in this tab", run: () => window.AirlockAdmin?.signOut(), portalOnly: true, keywords: "logout" }
  ];
  const TYPE_LABELS = { organization: "Organizations", org: "Organizations", customer: "Organizations", user: "Users", member: "Users", invitation: "Invitations", api_key: "API keys", key: "API keys", session: "Sessions", feedback: "Feedback", autopatch: "Autopatch", announcement: "Announcements", admin_event: "Admin events", event: "Events", flag: "Feature flags" };
  const typeLabel = type => TYPE_LABELS[String(type || "").toLowerCase()] || String(type || "Records").replace(/[_-]+/g, " ").replace(/^\w/, c => c.toUpperCase());

  function score(text, words) {
    const hay = text.toLowerCase();
    if (!words.every(w => hay.includes(w))) return -1;
    return words.reduce((s, w) => s + (hay.startsWith(w) ? 3 : hay.includes(` ${w}`) ? 2 : 1), 0);
  }
  function buildResults() {
    const q = palInput.value.trim();
    const words = q.toLowerCase().split(/\s+/).filter(Boolean);
    const out = [];
    const pages = allPages()
      .map(p => ({ p, s: words.length ? score(`${p.label} ${p.group} ${p.desc} ${p.route}`, words) : 1 }))
      .filter(x => x.s >= 0).sort((a, b) => b.s - a.s).slice(0, words.length ? 8 : 30)
      .map(({ p }) => ({ group: "Pages", icon: "&#8594;", label: p.label, sub: p.group ? `${p.group} · ${p.desc}` : p.desc, url: p.url || href(p.route), external: !!p.external }));
    out.push(...pages);
    ACTIONS.filter(a => inPortal || !a.portalOnly)
      .map(a => ({ a, s: words.length ? score(`${a.label} ${a.desc} ${a.keywords}`, words) : 1 }))
      .filter(x => x.s >= 0).sort((a, b) => b.s - a.s).slice(0, words.length ? 5 : 10)
      .forEach(({ a }) => out.push({ group: "Actions", icon: "&#9656;", label: a.label, sub: a.desc, url: a.route ? href(a.route) : "", run: a.run }));
    if (q.length >= 2) {
      const seen = new Set();
      const records = [];
      if (remote.q === q) remote.results.forEach(r => {
        const target = routeHref(r.route) || (r.organization_id ? href(`customers/${encodeURIComponent(r.organization_id)}`) : "");
        const id = `${r.type}|${r.id}`;
        if (seen.has(id)) return;
        seen.add(id);
        records.push({ group: typeLabel(r.type), icon: "&#9679;", label: r.title || r.id, sub: [r.subtitle, r.organization_id && r.type !== "organization" && !String(r.subtitle || "").includes(r.organization_id) ? r.organization_id : ""].filter(Boolean).join(" · "), url: target });
      });
      // Organizations the portal already loaded (real records) answer immediately, before the server does.
      const orgs = window.AirlockAdmin?.customers?.() || [];
      orgs.map(c => ({ c, s: score(`${c.name || ""} ${c.organization_id} ${c.plan_type || ""}`, words) })).filter(x => x.s >= 0).sort((a, b) => b.s - a.s).slice(0, 6).forEach(({ c }) => {
        const id = `organization|${c.organization_id}`;
        if (seen.has(id)) return;
        seen.add(id);
        records.push({ group: "Organizations", icon: "&#9679;", label: c.name || c.organization_id, sub: `${c.organization_id} · ${c.subscription_status || "unknown"} · ${c.plan_type || "starter"}`, url: href(`customers/${encodeURIComponent(c.organization_id)}`) });
      });
      const order = [];
      records.forEach(r => { if (!order.includes(r.group)) order.push(r.group); });
      order.sort((a, b) => (a === "Organizations" ? -1 : b === "Organizations" ? 1 : 0));
      order.forEach(g => out.push(...records.filter(r => r.group === g)));
    }
    return out;
  }
  function renderPalette() {
    palItems = buildResults();
    palActive = Math.min(palActive, Math.max(0, palItems.length - 1));
    let lastGroup = "";
    palList.innerHTML = palItems.map((item, i) => {
      const head = item.group !== lastGroup ? `<li class="sh-palGroup" role="presentation">${esc(item.group)}</li>` : "";
      lastGroup = item.group;
      return `${head}<li class="sh-palItem" role="option" id="shPal-${i}" data-i="${i}" aria-selected="${i === palActive}"><i aria-hidden="true">${item.icon}</i><b>${esc(item.label)}</b>${item.sub ? `<small>${esc(item.sub)}</small>` : ""}${item.external ? `<em>opens tab</em>` : ""}</li>`;
    }).join("") || `<li class="sh-palGroup" role="presentation">No matches</li>`;
    palInput.setAttribute("aria-activedescendant", palItems.length ? `shPal-${palActive}` : "");
    const q = palInput.value.trim();
    palStatus.textContent = q.length < 2 ? "Type two or more characters to search records." : remote.q === q && remote.status ? remote.status : remote.q !== q ? "Searching records…" : "";
    palList.querySelector('[aria-selected="true"]')?.scrollIntoView({ block: "nearest" });
  }
  function setActive(i) {
    if (!palItems.length) return;
    palActive = (i + palItems.length) % palItems.length;
    palList.querySelectorAll(".sh-palItem").forEach(li => li.setAttribute("aria-selected", String(Number(li.dataset.i) === palActive)));
    palInput.setAttribute("aria-activedescendant", `shPal-${palActive}`);
    palList.querySelector('[aria-selected="true"]')?.scrollIntoView({ block: "nearest" });
  }
  function activate(i) {
    const item = palItems[i];
    if (!item) return;
    closePalette(false);
    if (item.run) { item.run(); return; }
    if (!item.url) return;
    if (item.external) window.open(item.url, "_blank", "noopener");
    else if (item.url.startsWith("#")) location.hash = item.url;
    else location.href = item.url;
  }
  function searchRemote() {
    const q = palInput.value.trim();
    clearTimeout(palTimer);
    if (q.length < 2) { remote = { q: "", results: [], status: "" }; renderPalette(); return; }
    renderPalette();
    palTimer = setTimeout(async () => {
      const seq = ++palSeq;
      if (!canRequest()) { remote = { q, results: [], status: "Connect with a platform key to search records." }; renderPalette(); return; }
      try {
        const data = await request(`/platform/search?q=${encodeURIComponent(q)}&limit=20`);
        if (seq !== palSeq) return;
        const results = Array.isArray(data.results) ? data.results : [];
        remote = { q, results, status: results.length ? "" : "No matching records on the server." };
      } catch (err) {
        if (seq !== palSeq) return;
        remote = { q, results: [], status: err.status === 404 ? "Record search is not available on this server yet. Loaded organizations still match." : `Record search failed: ${err.message || err}` };
      }
      renderPalette();
    }, 220);
  }
  function openPalette() {
    if (!palette.hidden) return;
    closeMenus(); popovers.forEach(p => p.close()); closeDrawer();
    palReturn = document.activeElement;
    palette.hidden = false;
    palInput.value = "";
    palActive = 0;
    remote = { q: "", results: [], status: "" };
    renderPalette();
    palInput.focus();
  }
  function closePalette(refocus = true) {
    if (palette.hidden) return;
    palette.hidden = true;
    clearTimeout(palTimer);
    palSeq++;
    if (refocus && palReturn?.isConnected) palReturn.focus();
  }
  palInput.addEventListener("input", () => { palActive = 0; searchRemote(); });
  palInput.addEventListener("keydown", event => {
    if (event.key === "ArrowDown") { event.preventDefault(); setActive(palActive + 1); }
    else if (event.key === "ArrowUp") { event.preventDefault(); setActive(palActive - 1); }
    else if (event.key === "Home" && event.ctrlKey) { event.preventDefault(); setActive(0); }
    else if (event.key === "Enter") { event.preventDefault(); activate(palActive); }
    else if (event.key === "Escape") { event.preventDefault(); event.stopPropagation(); closePalette(); }
    else if (event.key === "Tab") event.preventDefault();
  });
  palList.addEventListener("pointermove", event => { const li = event.target.closest(".sh-palItem"); if (li && Number(li.dataset.i) !== palActive) setActive(Number(li.dataset.i)); });
  palList.addEventListener("click", event => { const li = event.target.closest(".sh-palItem"); if (li) activate(Number(li.dataset.i)); });
  palette.addEventListener("click", event => { if (event.target.closest("[data-pal-close]")) closePalette(); });
  searchButton?.addEventListener("click", openPalette);
  document.addEventListener("keydown", event => {
    if ((event.ctrlKey || event.metaKey) && !event.altKey && String(event.key).toLowerCase() === "k") {
      if (window.AirlockAdmin?.dialogOpen() || window.AirlockAdmin?.drawerOpen()) return;
      if (inPortal && !window.AirlockAdmin?.isConnected()) return;
      event.preventDefault();
      palette.hidden ? openPalette() : closePalette();
    }
  });

  window.AdminShell = { IA, allPages, href, setCurrent, setCounts, openPalette, closePalette, closeMenus, closeDrawer, loadNotifications, markAllRead, notifications: notes, isRead: id => readIds.has(String(id)), severity: sevOf, relTime, routeHref, operatorMenu: operatorPop };
  if (!inPortal) {
    if (/traffic\.html$/.test(location.pathname)) setCurrent("traffic");
    loadNotifications();
  }
})();
