(() => {
  "use strict";
  const $ = id => document.getElementById(id);
  const els = {
    key: $("platformKey"), role: $("platformRole"), status: $("status"), apiState: $("apiState"),
    load: $("loadBtn"), save: $("saveBtn"), clear: $("clearBtn"), reloadAll: $("reloadAllBtn"),
    refreshLogs: $("refreshLogsBtn"), healthBtn: $("healthBtn"), eventsBtn: $("eventsBtn"), readinessBtn: $("readinessBtn"),
    adminModeBody: $("adminModeBody"), telemetryBtn: $("telemetryBtn"), incidentsBtn: $("incidentsBtn"), tenantVerifyBtn: $("tenantVerifyBtn"),
    securityTruthBtn: $("securityTruthBtn"), autopatchBtn: $("autopatchBtn"), newAutopatch: $("newAutopatchBtn"),
    search: $("searchBox"), statusFilter: $("statusFilter"), customersBody: $("customersBody"),
    logsBody: $("logsBody"), riskBody: $("riskBody"), planBody: $("planBody"), healthBody: $("healthBody"), eventsBody: $("eventsBody"),
    readinessBody: $("readinessBody"), telemetryBody: $("telemetryBody"), incidentsBody: $("incidentsBody"), tenantVerifyBody: $("tenantVerifyBody"),
    securityTruthBody: $("securityTruthBody"), autopatchBody: $("autopatchBody"),
    drawer: $("drawer"), closeDrawer: $("closeDrawer"), closeDrawerBackdrop: $("closeDrawerBackdrop"),
    saveCustomer: $("saveCustomerBtn"), suspend: $("suspendBtn"), resume: $("resumeBtn"), auditPackage: $("auditPackageBtn"), saveFeatureFlag: $("saveFeatureFlagBtn"),
    quickGate: $("quickGateBtn"), quickTenant: $("quickTenantBtn"), dialog: $("actionDialog"),
    workspace: document.querySelector(".adminWorkspace"), signin: $("signinScreen")
  };
  const fmt = new Intl.NumberFormat();
  const STORAGE_KEYS = ["morrow_platform_admin_key", "morrow_platform_key", "morrow_platform_admin_role"];
  let customers = [];
  let selectedOrg = "";
  let loading = false;
  let connected = false;
  let sessionVersion = 0;
  let detailVersion = 0;
  let returnFocus = null;
  let identity = null;
  let lastMetrics = {};
  let lastIncidents = null;
  let accessItems = [];
  let keyItems = [];
  let sessionItems = [];
  let announcementItems = [];
  let lastRetentionPreview = null;
  let dialogState = null;
  const orgTable = { sort: "risk", dir: -1, page: 0, size: 25 };
  const requests = new Set();
  const sourceLabels = { password_account: "sign-in account", membership: "membership", accepted_invitation: "invitation" };

  // ── Formatting ────────────────────────────────────────────────────────────
  const esc = value => String(value ?? "").replace(/[&<>"']/g, ch => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[ch]));
  const asNum = value => Number.isFinite(Number(value)) ? Number(value) : 0;
  const text = (id, value) => { const el = $(id); if (el) el.textContent = String(value ?? "--"); };
  const empty = message => `<div class="empty">${esc(message)}</div>`;
  const emptyRow = (cols, message) => `<tr><td colspan="${cols}" class="empty">${esc(message)}</td></tr>`;
  // Loading, failure and retry states shared by every table and list in the console.
  const skeletonRows = (cols, rows = 4) => Array.from({ length: rows }, () => `<tr class="skeletonRow">${Array.from({ length: cols }, () => `<td><span class="skel"></span></td>`).join("")}</tr>`).join("");
  const skeletonList = (rows = 3) => `<div class="skeletonList">${Array.from({ length: rows }, () => `<span class="skel"></span>`).join("")}</div>`;
  const failBox = (message, retry) => `<div class="errorState" role="alert"><span>${esc(message)}</span>${retry ? `<button class="btn secondary small" type="button" data-retry="${esc(retry)}">Retry</button>` : ""}</div>`;
  const failRow = (cols, message, retry) => `<tr><td colspan="${cols}">${failBox(message, retry)}</td></tr>`;
  let statusTimer = 0;
  // Successes fade after a few seconds once the console is open; warnings and failures stay until replaced.
  const setStatus = (message, kind = "") => {
    if (!els.status) return;
    els.status.textContent = message; els.status.className = `status ${kind}`.trim();
    clearTimeout(statusTimer);
    if (kind === "ok" && connected) statusTimer = setTimeout(() => { if (els.status.textContent === message) els.status.textContent = ""; }, 6000);
  };
  const setApi = (message, kind = "") => { if (!els.apiState) return; els.apiState.textContent = message; els.apiState.className = `pill ${kind}`.trim(); };
  const note = (id, message, kind = "") => { const el = $(id); if (!el) return; el.textContent = message; el.className = `formNote ${kind}`.trim(); };
  const key = () => (els.key?.value || "").trim();
  const role = () => (identity?.role_bound ? identity.role : (els.role?.value || "owner")).trim();
  const canWrite = () => ["owner", "operator"].includes(role());
  const isOwner = () => role() === "owner";
  const enc = encodeURIComponent;

  function fmtTime(value, fallback = "—") {
    if (value === null || value === undefined || value === "") return fallback;
    const raw = String(value);
    const date = /^\d+(\.\d+)?$/.test(raw) ? new Date(Number(raw) < 1e12 ? Number(raw) * 1000 : Number(raw)) : new Date(raw);
    return Number.isNaN(date.getTime()) ? raw : date.toLocaleString();
  }
  function toLocalInput(iso) {
    const date = iso ? new Date(iso) : null;
    if (!date || Number.isNaN(date.getTime())) return "";
    const pad = n => String(n).padStart(2, "0");
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
  }
  const fromLocalInput = value => value ? new Date(value).toISOString() : null;
  function statusKind(status) {
    const s = String(status || "").toLowerCase();
    if (["ok", "pass", "passed", "active", "go", "healthy", "connected", "ready", "resolved", "approved", "available", "allow", "pr_ready", "clear", "off"].includes(s)) return "ok";
    if (["bad", "fail", "failed", "error", "suspended", "blocked", "no_go", "critical", "high", "rejected", "revoked", "disabled", "deny", "degraded", "on", "attention"].includes(s)) return "bad";
    return "warn";
  }
  const statusPill = status => { const s = String(status || "unknown").toLowerCase(); return `<span class="pill ${statusKind(s)}">${esc(s)}</span>`; };
  const riskPill = score => { const n = asNum(score); const cls = n >= 70 ? "bad" : n >= 35 ? "warn" : "ok"; return `<span class="pill ${cls}">${fmt.format(n)}</span>`; };
  const rowText = parts => parts.filter(Boolean).map(esc).join(" - ");
  const tags = values => (values || []).map(v => `<span class="tag">${esc(v)}</span>`).join("");
  function kv(entries) {
    const rows = entries.filter(([, v]) => v !== undefined && v !== null && v !== "");
    return rows.length ? `<dl class="kv">${rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("")}</dl>` : "";
  }
  const run = action => async event => { if (event?.preventDefault && event.type === "submit") event.preventDefault(); try { await action(event); } catch (err) { setStatus(err.message || String(err), "bad"); } };

  // ── API ───────────────────────────────────────────────────────────────────
  function errorMessage(data, res) {
    const detail = data && data.detail;
    if (Array.isArray(detail)) return detail.map(d => [Array.isArray(d.loc) ? d.loc.filter(p => p !== "body" && p !== "query").join(".") : "", d.msg].filter(Boolean).join(": ")).join("; ");
    if (detail && typeof detail === "object") return detail.message || detail.error || JSON.stringify(detail);
    return detail || `${res.status} ${res.statusText}`;
  }
  // SSO sign-in (admin-auth.js) authenticates with an HttpOnly session cookie instead of a key: no key is
  // sent or stored, and writes carry the CSRF token from /platform/whoami.
  const sessionAuth = { active: false, csrf: "" };
  async function request(path, opts = {}) {
    if (!key() && !sessionAuth.active) throw new Error("Enter the platform admin key first.");
    const version = sessionVersion;
    const controller = new AbortController();
    requests.add(controller);
    const timeout = setTimeout(() => controller.abort(), opts.timeout || 30000);
    try {
      const method = opts.method || "GET";
      const headers = sessionAuth.active ? {} : { "x-platform-key": key() };
      if (!opts.noRole) headers["x-platform-admin-role"] = role();
      if (sessionAuth.active && !["GET", "HEAD"].includes(method)) headers["x-csrf-token"] = sessionAuth.csrf;
      const init = { method, headers, signal: controller.signal, cache: "no-store", credentials: "same-origin" };
      if (opts.json !== undefined) { headers["Content-Type"] = "application/json"; init.body = JSON.stringify(opts.json); }
      const res = await fetch(path, init);
      if (version !== sessionVersion) throw new Error("Session changed. Reconnect to load data.");
      return res;
    } catch (err) {
      if (err.name === "AbortError") throw new Error("The request timed out or was cancelled.");
      throw err;
    } finally { clearTimeout(timeout); requests.delete(controller); }
  }
  async function api(path, opts = {}) {
    const res = await request(path, opts);
    const bodyText = await res.text();
    let data = {};
    try { data = bodyText ? JSON.parse(bodyText) : {}; } catch { data = { detail: bodyText }; }
    if (!res.ok) {
      const error = new Error(errorMessage(data, res)); error.status = res.status; error.code = (data && data.detail && data.detail.code) || "";
      // Destructive actions need a recent authenticator check: ask for a code once, then retry.
      if (error.code === "mfa_step_up_required" && !opts.stepUpRetried && window.AdminAuth?.stepUp && await window.AdminAuth.stepUp(error.message)) {
        return api(path, { ...opts, stepUpRetried: true });
      }
      throw error;
    }
    return data;
  }
  async function safeApi(path, opts) {
    try { return { ok: true, data: await api(path, opts) }; }
    catch (err) { return { ok: false, error: err.message || String(err), status: err.status, path }; }
  }
  const post = (path, json) => api(path, { method: "POST", json });
  async function download(path, fallbackName) {
    const res = await request(path, { timeout: 120000 });
    if (!res.ok) { let data = {}; try { data = JSON.parse(await res.text()); } catch { data = {}; } throw new Error(errorMessage(data, res)); }
    const match = /filename="?([^";]+)"?/i.exec(res.headers.get("content-disposition") || "");
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url; link.download = match ? match[1] : fallbackName;
    document.body.appendChild(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }

  // ── Identity & role controls ──────────────────────────────────────────────
  function renderIdentity() {
    const name = identity?.operator || (connected ? "Platform operator" : "");
    text("operatorIdentity", name || "Not signed in");
    text("operatorRoleText", connected ? `${role()}${canWrite() ? "" : " · read-only"}` : "No role");
    text("operatorAvatar", name ? name.replace(/[^A-Za-z0-9]/g, "").slice(0, 2).toUpperCase() || "OP" : "?");
    text("operatorName", name || "Not signed in");
    text("operatorMeta", !connected ? "Connect with a platform credential." : identity?.auth_method === "sso" ? `SSO · ${role()} role from the operator roster` : identity?.role_bound ? `Named operator key · ${role()} role bound to the key` : `Shared platform key · acting as ${role()}${identity?.ceiling_role ? ` (ceiling ${identity.ceiling_role})` : ""}`);
    const roleField = $("roleField");
    if (roleField) roleField.hidden = !!(connected && identity?.role_bound);
    renderRemember();
  }
  function remembered() { try { return !!sessionStorage.getItem("morrow_platform_admin_key"); } catch { return false; } }
  function renderRemember() {
    const on = remembered();
    els.save?.setAttribute("aria-pressed", String(on));
    text("rememberState", on ? "on" : "off");
  }
  function applyRoleControls() {
    const write = canWrite();
    const owner = isOwner();
    document.querySelectorAll("[data-write]").forEach(el => { el.disabled = !write; el.title = write ? "" : "This action requires the owner or operator role."; });
    document.querySelectorAll("[data-owner]").forEach(el => { el.disabled = !owner; el.title = owner ? "" : "This action requires the owner role."; });
    renderIdentity();
  }
  function applyIdentity(who) {
    identity = who || null;
    const allowed = who?.allowed_roles?.length ? who.allowed_roles : ["owner", "operator", "support", "auditor"];
    [...els.role.options].forEach(option => { option.disabled = !allowed.includes(option.value); });
    if (who?.role_bound) {
      els.role.value = who.role;
      els.role.disabled = true;
    } else {
      els.role.disabled = false;
      if (!allowed.includes(els.role.value)) els.role.value = allowed[0] || "auditor";
    }
    const binding = $("roleBindingNote");
    if (binding && who) {
      binding.textContent = who.auth_method === "sso"
        ? `Signed in with SSO as ${who.email || who.operator}. The ${who.role} role comes from the operator roster and every change is recorded under your email.`
        : who.role_bound
        ? `Signed in as named operator ${who.operator}. The ${who.role} role is bound to this key and recorded on every change.`
        : `Shared platform key (ceiling: ${who.ceiling_role}). Requests run as the role selected above and the audit trail records "${who.operator}". Named operator keys give every administrator their own identity.`;
    }
    applyRoleControls();
  }

  // ── Pages ─────────────────────────────────────────────────────────────────
  // Routing lives in admin-views.js; these are the loaders for the pages built on the
  // original portal panels. Each runs when its page is opened while connected.
  function showView(route) { if (window.AdminApp) window.AdminApp.go(route); else location.hash = `#/${route}`; }
  const viewLoaders = {
    users: () => loadAccess(),
    invitations: () => loadInvites(),
    "rate-limits": () => loadRateLimits(),
    operators: () => (isOwner() ? loadOperators() : Promise.resolve()),
    "api-keys": () => loadKeys(),
    sessions: () => loadSessions(),
    data: () => Promise.allSettled([loadRetentionPolicy(), loadStateCoverage()]),
    health: () => Promise.allSettled([loadObservability(), loadLogStorage()]),
    maintenance: () => loadMaintenance(),
    announcements: () => loadAnnouncements(),
    audit: () => loadEvents(0)
  };
  async function loadViewData(name) { const loader = viewLoaders[name]; if (loader) await loader(); }
  function jumpTo(view) {
    if (els.drawer.classList.contains("open")) {
      const org = selectedOrg;
      closeCustomer();
      if (org) selectOrg(org);
    }
    showView(view);
    window.scrollTo(0, 0);
  }

  // ── Dialog ────────────────────────────────────────────────────────────────
  function setInert() {
    const dialogOpen = !els.dialog.hidden;
    const drawerOpen = els.drawer.classList.contains("open");
    els.workspace.inert = dialogOpen || drawerOpen;
    els.drawer.inert = !drawerOpen || dialogOpen;
  }
  function fieldHtml(field) {
    const label = `<span class="label">${esc(field.label)}</span>`;
    const name = esc(field.name);
    if (field.type === "select") {
      return `<label>${label}<select name="${name}">${field.options.map(o => `<option value="${esc(o.value)}"${String(o.value) === String(field.value ?? "") ? " selected" : ""}>${esc(o.label)}</option>`).join("")}</select></label>`;
    }
    return `<label>${label}<input name="${name}" type="${field.type === "number" ? "number" : "text"}" value="${esc(field.value ?? "")}" autocomplete="off"></label>`;
  }
  function openDialog(config) {
    return new Promise(resolve => {
      if (dialogState) dialogState.resolve(null);
      dialogState = { resolve, config, back: document.activeElement };
      text("actionDialogTitle", config.title || "Confirm");
      text("actionDialogBody", config.body || "");
      $("actionDialogFields").innerHTML = (config.fields || []).map(fieldHtml).join("");
      $("actionDialogReasonField").hidden = !config.reason;
      $("actionDialogReason").value = "";
      $("actionDialogConfirmField").hidden = !config.confirmText;
      $("actionDialogConfirm").value = "";
      if (config.confirmText) text("actionDialogConfirmLabel", `Type ${config.confirmText} to confirm`);
      $("actionDialogSecret").hidden = !config.secret;
      text("actionDialogSecretValue", config.secret || "");
      text("actionDialogCopy", "Copy");
      text("actionDialogError", "");
      const submit = $("actionDialogSubmit");
      submit.textContent = config.submitLabel || "Confirm";
      submit.className = config.danger ? "btn danger" : "btn";
      $("actionDialogCancel").hidden = !!config.noCancel;
      els.dialog.hidden = false;
      setInert();
      const firstField = $("actionDialogFields").querySelector("input, select");
      (firstField || (config.reason ? $("actionDialogReason") : null) || (config.confirmText ? $("actionDialogConfirm") : null) || submit).focus();
    });
  }
  function closeDialog(result) {
    if (!dialogState) return;
    const { resolve, back } = dialogState;
    dialogState = null;
    els.dialog.hidden = true;
    $("actionDialogFields").innerHTML = "";
    text("actionDialogSecretValue", "");
    setInert();
    if (back?.isConnected) back.focus();
    resolve(result);
  }
  $("actionDialogForm").addEventListener("submit", event => {
    event.preventDefault();
    if (!dialogState) return;
    const { config } = dialogState;
    const values = {};
    (config.fields || []).forEach(field => { const input = $("actionDialogFields").querySelector(`[name="${field.name}"]`); values[field.name] = input ? input.value : ""; });
    if (config.reason) {
      values.reason = $("actionDialogReason").value.trim();
      if (values.reason.length < 3) { text("actionDialogError", "Enter a reason of at least 3 characters. It is recorded in the audit trail."); $("actionDialogReason").focus(); return; }
    }
    if (config.confirmText && $("actionDialogConfirm").value.trim() !== config.confirmText) {
      text("actionDialogError", `Type ${config.confirmText} exactly to confirm.`);
      $("actionDialogConfirm").focus();
      return;
    }
    const problem = config.validate ? config.validate(values) : "";
    if (problem) { text("actionDialogError", problem); return; }
    closeDialog(values);
  });
  $("actionDialogCancel").addEventListener("click", () => closeDialog(null));
  $("actionDialogBackdrop").addEventListener("click", () => closeDialog(null));
  $("actionDialogCopy").addEventListener("click", async () => {
    const value = $("actionDialogSecretValue").textContent;
    try { await navigator.clipboard.writeText(value); text("actionDialogCopy", "Copied"); text("actionDialogError", ""); }
    catch { text("actionDialogError", "Copy is blocked in this browser. Select the value and copy it manually."); }
  });
  const showSecret = (title, body, secret) => openDialog({ title, body, secret, submitLabel: "I have stored it", noCancel: true });
  function focusables(container) {
    return [...container.querySelectorAll("button:not(:disabled), input:not(:disabled):not([type=hidden]), select:not(:disabled), textarea:not(:disabled), a[href], summary")].filter(el => el.getClientRects().length);
  }
  document.addEventListener("keydown", event => {
    const dialogOpen = !els.dialog.hidden;
    const drawerOpen = els.drawer.classList.contains("open");
    if (!dialogOpen && !drawerOpen) return;
    if (event.key === "Escape") { event.preventDefault(); if (dialogOpen) closeDialog(null); else closeCustomer(); return; }
    if (event.key !== "Tab") return;
    const items = focusables(dialogOpen ? $("actionDialogForm") : els.drawer);
    if (!items.length) return;
    const first = items[0], last = items[items.length - 1];
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
  });

  // ── Organizations ─────────────────────────────────────────────────────────
  function populateOrgSelects() {
    const orgs = customers.map(c => ({ id: String(c.organization_id), name: String(c.name || c.organization_id) })).sort((a, b) => a.name.localeCompare(b.name));
    document.querySelectorAll("select[data-org-select]").forEach(select => {
      const previous = select.value;
      const first = select.hasAttribute("data-org-all") ? "All organizations" : "Choose organization";
      select.innerHTML = `<option value="">${first}</option>` + orgs.map(o => `<option value="${esc(o.id)}">${esc(o.name)}${o.name !== o.id ? ` (${esc(o.id)})` : ""}</option>`).join("");
      if (previous && orgs.some(o => o.id === previous)) select.value = previous;
    });
  }
  function selectOrg(org) {
    document.querySelectorAll("select[data-org-select]").forEach(select => { if ([...select.options].some(o => o.value === org)) select.value = org; });
  }

  // ── Overview & customers ──────────────────────────────────────────────────
  function metric(id, value) { text(id, value == null ? "--" : fmt.format(asNum(value))); }
  const sortKeys = {
    name: c => String(c.name || c.organization_id || "").toLowerCase(),
    status: c => String(c.subscription_status || ""),
    plan: c => String(c.plan_type || "starter"),
    risk: c => asNum(c.risk_score),
    scans: c => asNum(c.scan_count),
    assets: c => asNum(c.asset_count),
    users: c => asNum(c.user_count),
    login: c => { const t = Date.parse(c.last_login_at || ""); return Number.isNaN(t) ? 0 : t; }
  };
  function filteredCustomers() {
    const q = (els.search?.value || "").toLowerCase().trim();
    const sf = (els.statusFilter?.value || "").toLowerCase().trim();
    const pf = ($("planFilter")?.value || "").toLowerCase().trim();
    const key = sortKeys[orgTable.sort] || sortKeys.risk;
    return customers
      .filter(c => (!q || `${c.name || ""} ${c.organization_id || ""} ${c.plan_type || ""}`.toLowerCase().includes(q)) && (!sf || String(c.subscription_status || "").toLowerCase() === sf) && (!pf || String(c.plan_type || "starter").toLowerCase() === pf))
      .sort((a, b) => {
        const x = key(a), y = key(b);
        const order = typeof x === "number" ? x - y : String(x).localeCompare(String(y));
        return order * orgTable.dir || String(a.name || a.organization_id).localeCompare(String(b.name || b.organization_id));
      });
  }
  function visibleCustomers() {
    const rows = filteredCustomers();
    const pages = Math.max(1, Math.ceil(rows.length / orgTable.size));
    orgTable.page = Math.min(orgTable.page, pages - 1);
    const start = orgTable.page * orgTable.size;
    return { rows, pages, start, visible: rows.slice(start, start + orgTable.size) };
  }
  function renderPlanFilter() {
    const select = $("planFilter");
    if (!select) return;
    const previous = select.value;
    const plans = [...new Set(customers.map(c => String(c.plan_type || "starter")))].sort();
    select.innerHTML = `<option value="">All plans</option>` + plans.map(p => `<option value="${esc(p.toLowerCase())}">${esc(p)}</option>`).join("");
    if (plans.some(p => p.toLowerCase() === previous)) select.value = previous;
  }
  function renderCustomers() {
    if (!els.customersBody) return;
    document.querySelectorAll("#customers th[aria-sort]").forEach(th => {
      const sort = th.querySelector("[data-sort]")?.dataset.sort;
      th.setAttribute("aria-sort", sort === orgTable.sort ? (orgTable.dir > 0 ? "ascending" : "descending") : "none");
    });
    const { rows, pages, start, visible } = visibleCustomers();
    const info = $("orgPageInfo"), prev = $("orgPrev"), next = $("orgNext");
    if (info) info.textContent = rows.length ? `${fmt.format(start + 1)}-${fmt.format(start + visible.length)} of ${fmt.format(rows.length)}` : "No results";
    if (prev) prev.disabled = orgTable.page <= 0;
    if (next) next.disabled = orgTable.page >= pages - 1;
    if (!customers.length) { els.customersBody.innerHTML = connected ? emptyRow(8, "No customer organizations yet. Create one with New customer.") : emptyRow(8, "Load the portal to see customers."); return; }
    if (!rows.length) { els.customersBody.innerHTML = emptyRow(8, "No customers match the filter."); return; }
    els.customersBody.innerHTML = visible.map(c => `<tr class="customerRow" data-org="${esc(c.organization_id)}" tabindex="0" aria-label="Open Customer 360 for ${esc(c.name || c.organization_id)}">
      <td><b>${esc(c.name || c.organization_id)}</b><br><span class="mono muted">${esc(c.organization_id)}</span></td>
      <td>${statusPill(c.subscription_status)}</td><td>${esc(c.plan_type || "starter")}</td><td>${riskPill(c.risk_score || 0)}</td>
      <td class="num">${fmt.format(asNum(c.scan_count))}</td><td class="num">${fmt.format(asNum(c.asset_count))}</td><td class="num">${fmt.format(asNum(c.user_count))}</td><td class="mono">${esc(fmtTime(c.last_login_at, "Not observed"))}</td>
    </tr>`).join("");
  }
  const open360 = org => { location.hash = `#/customers/${enc(org)}`; };
  els.customersBody?.addEventListener("click", event => { const row = event.target.closest(".customerRow"); if (row) open360(row.dataset.org); });
  els.customersBody?.addEventListener("keydown", event => {
    const row = event.target.closest(".customerRow");
    if (row && (event.key === "Enter" || event.key === " ")) { event.preventDefault(); open360(row.dataset.org); }
  });
  document.querySelector("#customers thead")?.addEventListener("click", event => {
    const button = event.target.closest("[data-sort]");
    if (!button) return;
    const sort = button.dataset.sort;
    if (orgTable.sort === sort) orgTable.dir *= -1;
    else { orgTable.sort = sort; orgTable.dir = ["name", "status", "plan"].includes(sort) ? 1 : -1; }
    orgTable.page = 0;
    renderCustomers();
  });
  $("orgPrev")?.addEventListener("click", () => { orgTable.page = Math.max(0, orgTable.page - 1); renderCustomers(); });
  $("orgNext")?.addEventListener("click", () => { orgTable.page += 1; renderCustomers(); });
  $("planFilter")?.addEventListener("change", () => { orgTable.page = 0; renderCustomers(); });
  $("orgExportBtn")?.addEventListener("click", () => {
    const { visible } = visibleCustomers();
    if (!visible.length) { setStatus("No visible rows to export.", "warn"); return; }
    const cell = value => { const s = String(value ?? ""); return /[",\r\n]/.test(s) || /^[=+\-@]/.test(s) ? `"${(/^[=+\-@]/.test(s) ? "'" : "") + s.replace(/"/g, '""')}"` : s; };
    const head = ["organization_id", "name", "status", "plan", "risk_score", "scans", "assets", "users", "last_login_at"];
    const lines = [head.join(",")].concat(visible.map(c => [c.organization_id, c.name, c.subscription_status, c.plan_type || "starter", c.risk_score, c.scan_count, c.asset_count, c.user_count, c.last_login_at].map(cell).join(",")));
    const url = URL.createObjectURL(new Blob([lines.join("\r\n") + "\r\n"], { type: "text/csv" }));
    const link = document.createElement("a");
    link.href = url; link.download = "pq-organizations.csv";
    document.body.appendChild(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
    setStatus(`Exported ${fmt.format(visible.length)} visible organization row(s).`, "ok");
  });
  function renderLogs(items, target = els.logsBody) {
    if (!target) return;
    if (!items?.length) { target.innerHTML = empty("No matching authentication events in retained history."); return; }
    target.innerHTML = items.map(i => `<div class="logItem"><b>${esc(i.event_type || "login")} ${statusPill(Number(i.status_code) >= 400 ? "rejected" : "ok")}</b><span class="mono">${esc(i.user_id || "Unverified identity")} / ${esc(i.organization_id || "No verified organization")}</span><span>${rowText([i.login_method, fmtTime(i.created_at)])}</span><span>${esc(i.ip_address || "IP unavailable")} / HTTP ${esc(i.status_code || "unknown")}</span></div>`).join("");
  }
  const authEventsPath = () => {
    const query = new URLSearchParams({ limit: "80", event_type: $("authEventType")?.value || "" });
    const user = ($("authUserFilter")?.value || "").trim();
    const since = $("authSince")?.value || "";
    if (user) query.set("user_id", user);
    if (since) query.set("since", since);
    return `/platform/logins?${query}`;
  };
  function renderAuthHistory(data) {
    renderLogs(data.items || []);
    const storage = data.storage || {};
    const gaps = Object.values(storage.writes || {}).reduce((n, item) => n + Number(item.failed_writes || 0), 0);
    text("loggingHealth", `Storage: ${storage.status || "unverified"} (${storage.backend || "unknown"}). Authentication retention: ${storage.auth_retention_days ?? "unknown"} days. ${gaps} write failure(s) observed in this process. Not a complete session recording.`);
  }
  async function loadAuthHistory() {
    try { renderAuthHistory(await api(authEventsPath())); }
    catch (err) { text("loggingHealth", "Storage unavailable; retained history is unknown, not empty."); els.logsBody.innerHTML = empty("Authentication history unavailable."); throw err; }
  }
  function renderRisk(items, neverActive) {
    const count = items?.length || 0;
    text("riskCount", `${fmt.format(count)} risk`);
    text("mAtRisk", fmt.format(count));
    if (neverActive != null) text("mNeverActive", `${fmt.format(asNum(neverActive))} never signed in`);
    if (!els.riskBody) return;
    if (!count) { els.riskBody.innerHTML = empty("No activation risk returned."); return; }
    els.riskBody.innerHTML = items.map(c => `<div class="riskItem"><b>${esc(c.name || c.organization_id)} ${riskPill(c.risk_score || 0)}</b><span class="mono">${esc(c.organization_id)}</span><span>Last observed sign-in: ${esc(fmtTime(c.last_login_at, "Not observed"))} - scans: ${fmt.format(asNum(c.scan_count))}</span></div>`).join("");
  }
  function renderPlans(planBreakdown) {
    if (!els.planBody) return;
    const entries = Object.entries(planBreakdown || {}).sort((a, b) => asNum(b[1]) - asNum(a[1]));
    const max = Math.max(1, ...entries.map(([, n]) => asNum(n)));
    if (!entries.length) { els.planBody.innerHTML = empty("No plan data available."); return; }
    els.planBody.innerHTML = entries.map(([p, c]) => `<div class="riskItem"><b>${esc(p)}</b><span>${fmt.format(asNum(c))} customer(s)</span><div class="bar"><i style="width:${Math.max(5, Math.round((asNum(c) / max) * 100))}%"></i></div></div>`).join("");
  }
  function renderHealth(data) {
    const entries = Object.entries(data.checks || {});
    const bad = entries.filter(([, c]) => statusKind(c.status) === "bad").length;
    const warn = entries.filter(([, c]) => statusKind(c.status) === "warn").length;
    text("mHealthState", bad ? `${bad} bad` : warn ? `${warn} warn` : entries.length ? "OK" : "--");
    if (!els.healthBody) return;
    els.healthBody.innerHTML = entries.map(([name, c]) => `<div class="healthItem"><b>${esc(name)} ${statusPill(c.status)}</b><span>${esc(c.detail || "Ready")}</span></div>`).join("") || empty("No health checks returned.");
  }
  function renderReadiness(data) {
    const checks = data.checks || [];
    if (!els.readinessBody) return;
    els.readinessBody.innerHTML = checks.length ? checks.map(c => `<div class="event"><b>${esc(c.label)} ${statusPill(c.status === "pass" ? "pass" : "blocked")}</b><span>${esc(c.detail || "")}</span><span>${esc(c.fix || "")}</span></div>`).join("") : empty("No readiness checks returned.");
  }
  function renderTelemetry(metrics = {}, health = {}, readiness = {}, securityTruth = {}) {
    const alerts = [];
    Object.entries(health.checks || {}).forEach(([name, c]) => { if (statusKind(c.status) !== "ok") alerts.push(["Health", statusKind(c.status), `${name}: ${c.detail || c.status || "not ready"}`]); });
    (readiness.checks || []).forEach(c => { if (String(c.status || "").toLowerCase() !== "pass") alerts.push(["Readiness", "warn", `${c.label || "Gate"}: ${c.fix || c.detail || "requires action"}`]); });
    if (asNum(securityTruth.open_high_critical) > 0) alerts.push(["Security Truth", "bad", `${fmt.format(asNum(securityTruth.open_high_critical))} high/critical external finding(s) open.`]);
    if (asNum(securityTruth.blocked_write_path_changes) > 0) alerts.push(["Write-path", "warn", `${fmt.format(asNum(securityTruth.blocked_write_path_changes))} change(s) blocked by guardrails.`]);
    if (asNum(metrics.customers_total) > 0 && asNum(metrics.customers_active_7d) === 0) alerts.push(["Activation", "warn", "No customer activity in the last 7 days."]);
    text("mOpenAlerts", fmt.format(alerts.length));
    if (!els.telemetryBody) return;
    if (!alerts.length) alerts.push(["All clear", "ok", "No active operational alerts from the current telemetry snapshot."]);
    const summary = `<div class="riskItem"><b>${fmt.format(alerts.filter(a => a[1] !== "ok").length)} active alert(s) ${statusPill(alerts.some(a => a[1] === "bad") ? "blocked" : alerts.some(a => a[1] === "warn") ? "warn" : "ok")}</b><span>${fmt.format(asNum(metrics.total_scans))} scans - ${fmt.format(asNum(metrics.total_assets))} assets - ${fmt.format(asNum(metrics.logins_last_24h))} login(s) in 24h</span></div>`;
    els.telemetryBody.innerHTML = summary + alerts.map(([scope, state, copy]) => `<div class="event"><b>${esc(scope)} ${statusPill(state)}</b><span>${esc(copy)}</span></div>`).join("");
  }
  function renderAdminMode(data = {}) {
    const warnings = data.warnings || [];
    const strict = data.security?.feature_flags_strict ? "strict flags" : "kill-switch flags";
    if (els.adminModeBody) els.adminModeBody.innerHTML = `<b>Admin mode: ${esc(data.mode || "unknown")} ${statusPill(data.mode === "production" ? "active" : "warn")}</b><span>${esc(data.environment || "local")} - CSP ${data.security?.csp_enabled ? "on" : "off"} - ${strict}</span>${warnings.length ? `<span>${esc(warnings.join(" "))}</span>` : `<span>Production guardrails are visible from this route.</span>`}`;
  }

  // ── Security & readiness ──────────────────────────────────────────────────
  async function loadGate() {
    const body = $("gateBody");
    try {
      const d = await api("/platform/go-live-gate");
      const go = d.status === "go" && d.go_live_allowed === true;
      text("mGateState", go ? "GO" : "NO-GO");
      const blockers = d.failed_required_checks || d.blockers || [];
      const warnings = d.warnings || [];
      const advisories = d.advisories || [];
      const checks = d.checks || [];
      const rows = blockers.map(check => `<div class="event"><b>${esc(check.label || check.key || "Required check")} ${statusPill("blocked")}</b><span>${esc(check.detail || check)}</span>${check.fix ? `<span>Action: ${esc(check.fix)}</span>` : ""}</div>`).join("");
      const head = `<div class="riskItem"><b>Launch gate ${statusPill(go ? "go" : "no_go")}</b><span>${fmt.format(blockers.length)} blocker(s) - ${fmt.format(warnings.length)} warning(s) - ${fmt.format(advisories.length)} advisory note(s)</span></div>`;
      const warningRows = warnings.map(w => `<div class="event"><b>Warning ${statusPill("warn")}</b><span>${esc(w)}</span></div>`).join("");
      const advisoryRows = advisories.map(a => `<div class="event"><b>Advisory <span class="pill">does not block</span></b><span>${esc(a)}</span></div>`).join("");
      const manual = (d.manual_exit_criteria || []).map(item => `<div class="event"><b>Manual exit criterion</b><span>${esc(item)}</span></div>`).join("");
      const all = checks.length ? `<details class="detailsBlock"><summary>All ${fmt.format(checks.length)} automated checks</summary>${checks.map(c => `<div class="event"><b>${esc(c.label || c.key)} ${statusPill(c.status === "pass" ? "pass" : "blocked")}</b><span>${esc(c.detail || "")}</span></div>`).join("")}</details>` : "";
      if (body) body.innerHTML = head + rows + warningRows + advisoryRows + (go ? empty("Automated configuration checks pass. Complete the manual exit criteria before launch.") : "") + manual + all;
      return d;
    } catch (err) {
      text("mGateState", "blocked");
      if (body) body.innerHTML = failBox(`Gate unavailable: ${err.message || err}`, "gate");
      throw err;
    }
  }
  async function loadTraffic() {
    const body = $("trafficBody");
    try {
      const d = await api("/platform/traffic/summary");
      const boundary = d.privacy_boundary;
      text("mDataBoundary", !boundary ? "Unknown" : [boundary.request_bodies_stored, boundary.query_strings_stored, boundary.authorization_headers_stored].every(value => value === false) ? "Metadata only" : "Review policy");
      const totals = d.totals || {};
      const ips = d.top_ips || d.ips || [];
      metric("mTrafficEvents", totals.events_in_buffer ?? d.event_count ?? d.total_events);
      if (body) body.innerHTML = `<div class="riskItem"><b>${fmt.format(asNum(totals.events_in_buffer ?? d.event_count ?? d.total_events))} events - ${fmt.format(asNum(totals.unique_ips ?? d.unique_ips ?? ips.length))} source IPs</b><span>${fmt.format(asNum(totals.blocked ?? d.blocked))} blocked - ${fmt.format(asNum(totals.rate_limited ?? d.rate_limited))} rate limited - ${fmt.format(asNum(totals.errors ?? d.errors))} errors</span></div>` + (ips.slice(0, 10).map(i => `<div class="logItem"><b>${esc(i.source_ip || i.ip || "unknown")}</b><span>${fmt.format(asNum(i.requests))} requests</span><span>${fmt.format(asNum(i.blocked))} blocked - ${fmt.format(asNum(i.rate_limited))} limited</span><span class="mono">${esc(fmtTime(i.last_seen, ""))}</span></div>`).join("") || empty("No traffic captured yet."));
      return d;
    } catch (err) {
      text("mTrafficEvents", "--"); text("mDataBoundary", "Unknown");
      if (body) body.innerHTML = failBox(`Traffic unavailable: ${err.message || err}`, "traffic");
      throw err;
    }
  }
  function renderTenantProbe(data) {
    const checks = data.checks || [];
    if (!els.tenantVerifyBody) return;
    const body = checks.map(c => `<div class="event"><b>${esc(c.key)} ${statusPill(c.status === "pass" ? "pass" : "blocked")}</b><span>${esc(c.status || "")}</span></div>`).join("");
    els.tenantVerifyBody.innerHTML = `<div class="riskItem"><b>Tenant isolation ${statusPill(data.status === "pass" ? "pass" : "blocked")}</b><span>${esc(fmtTime(data.generated_at, ""))}</span></div>` + (body || empty("No probe checks returned."));
  }
  async function runTenantProbe() {
    showView("isolation");
    if (els.tenantVerifyBody) els.tenantVerifyBody.innerHTML = empty("Running tenant isolation probe...");
    try { renderTenantProbe(await post("/platform/tenant-isolation/verify")); }
    catch (err) { els.tenantVerifyBody.innerHTML = empty(`Probe failed: ${err.message}`); throw err; }
  }
  function renderSecurityTruth(data = {}) {
    if (!els.securityTruthBody) return;
    const findings = data.recent_findings || [];
    const counts = obj => Object.entries(obj || {}).map(([k, v]) => `${k} ${fmt.format(asNum(v))}`);
    const head = `<div class="riskItem"><b>${fmt.format(asNum(data.open_high_critical))} open high/critical ${statusPill(asNum(data.blocked_write_path_changes) ? "blocked" : "ok")}</b><span>Severity: ${esc(counts(data.counts_by_severity).join(" - ") || "No findings")}</span><span>Status: ${esc(counts(data.counts_by_status).join(" - ") || "none")} · Tools: ${esc(counts(data.counts_by_tool).join(" - ") || "none")}</span><span>${fmt.format(asNum(data.blocked_write_path_changes))} blocked write-path change(s)</span></div>`;
    const rows = findings.slice(0, 20).map(f => `<div class="event"><b>#${fmt.format(asNum(f.id))} ${esc(f.title || "Finding")} ${statusPill(f.severity || "medium")}</b><span class="mono">${esc(f.organization_id || "org")} - ${esc(f.tool_source || "tool")}</span><span>${esc(f.repo || f.resource_id || "unscoped")} - ${esc(f.status || "open")}</span><div class="row"><button class="btn secondary small" data-write data-st-action="dry-run" data-id="${esc(f.id)}" type="button">Dry-run write-path</button><button class="btn danger small" data-write data-st-action="execute" data-id="${esc(f.id)}" type="button">Request fix&hellip;</button></div></div>`).join("");
    const guardrails = (data.recent_guardrails || []).slice(0, 10).map(g => `<div class="event"><b>${esc(g.action || "guardrail")} ${statusPill(g.decision || "allow")}</b><span class="mono">${esc(g.actor_id || "")} - ${esc(g.resource_id || "")}</span><span>${esc(fmtTime(g.created_at, ""))}</span></div>`).join("");
    els.securityTruthBody.innerHTML = head + (rows || empty("No external findings have been ingested yet.")) + (guardrails ? `<details class="detailsBlock"><summary>Recent guardrail evaluations</summary>${guardrails}</details>` : "");
    applyRoleControls();
  }
  els.securityTruthBody?.addEventListener("click", run(async event => {
    const button = event.target.closest("[data-st-action]");
    if (!button) return;
    const id = button.dataset.id;
    if (button.dataset.stAction === "execute") {
      const ok = await openDialog({ title: `Request a fix for finding #${id}`, body: "This creates a real write-path fix request for the finding's organization, subject to guardrails and that organization's write_path feature flag. It does not merge anything.", submitLabel: "Request fix", danger: true });
      if (!ok) return;
    }
    const result = await post(`/platform/security-truth/findings/${enc(id)}/write-path`, { dry_run: button.dataset.stAction !== "execute" });
    setStatus(`Write-path ${button.dataset.stAction === "execute" ? "request" : "dry run"} for finding #${id}: ${result.status || result.decision || "done"}${result.request_id ? ` (${result.request_id})` : ""}.`, "ok");
    renderSecurityTruth(await api("/platform/security-truth?limit=80"));
  }));
  async function loadRlsPlan() {
    const body = $("rlsBody");
    try {
      const d = await api("/platform/rls-plan");
      const steps = (d.operator_steps || []).map(s => `<li>${esc(s)}</li>`).join("");
      body.innerHTML = `<div class="riskItem"><b>RLS plan ${statusPill(d.status || "unknown")}</b><span>App role ${esc(d.app_role || "")} - setting ${esc(d.org_setting || "")}</span></div><div class="event"><b>Organization-scoped tables</b><div>${tags(d.tables)}</div></div>${(d.sqlite_only_tables || []).length ? `<div class="event"><b>SQLite-only tables (not covered)</b><div>${tags(d.sqlite_only_tables)}</div></div>` : ""}${steps ? `<div class="event"><b>Operator steps</b><ol class="guide">${steps}</ol></div>` : ""}<details class="detailsBlock"><summary>Generated SQL</summary><pre class="codeBlock">${esc(d.sql || "")}</pre></details>`;
    } catch (err) { body.innerHTML = failBox(`RLS plan unavailable: ${err.message}`, "rls"); throw err; }
  }

  // ── Incidents ─────────────────────────────────────────────────────────────
  function renderIncidents(incidents = {}, abuse = {}) {
    const items = incidents.incidents || [];
    const rate = abuse.rate_limited_events || [];
    if (els.incidentsBody) {
      const head = `<div class="riskItem"><b>${fmt.format(items.length)} incident(s) ${statusPill(items.length ? "blocked" : "ok")}</b><span>${fmt.format(rate.length)} recent rate-limit event(s) - ${fmt.format(asNum(abuse.login_events_last_24h))} sign-in(s) in 24h</span></div>`;
      const rows = items.slice(0, 25).map(i => `<div class="event"><b>${esc(i.title || "Incident")} ${statusPill(i.severity === "high" ? "blocked" : "warn")}</b><span class="mono">${esc(i.organization_id || "platform")} - ${esc(i.category || "ops")}</span><span>${esc(i.detail || "")}</span></div>`).join("");
      els.incidentsBody.innerHTML = head + (rows || empty("No active incidents from in-process telemetry."));
    }
    const abuseBody = $("abuseBody");
    if (abuseBody) {
      const bars = (obj, label) => {
        const entries = Object.entries(obj || {}).sort((a, b) => b[1] - a[1]).slice(0, 10);
        const max = Math.max(1, ...entries.map(([, n]) => asNum(n)));
        return entries.length ? `<div class="sectionTitle">${esc(label)}</div>` + entries.map(([k, n]) => `<div class="riskItem"><b class="mono">${esc(k)}</b><span>${fmt.format(asNum(n))} limited request(s)</span><div class="bar"><i style="width:${Math.max(5, Math.round((asNum(n) / max) * 100))}%"></i></div></div>`).join("") : "";
      };
      const recent = rate.slice(-8).reverse().map(i => `<div class="event"><b>Rate limit ${statusPill("warn")}</b><span class="mono">${esc(i.organization_id || "unknown")} - ${esc(i.source || "")}</span><span>${rowText([i.path || "", fmtTime(i.created_at, "")])}</span></div>`).join("");
      abuseBody.innerHTML = (bars(abuse.rate_limited_by_org, "By organization") + bars(abuse.rate_limited_by_path, "By route") + recent) || empty("No rate limiting observed in this process.");
      const rateTop = $("rateTopBody");
      if (rateTop) rateTop.innerHTML = abuseBody.innerHTML;
    }
    lastIncidents = { incidents: items.length, rateLimited: rate.length };
  }
  async function loadIncidents() {
    const [incidents, abuse] = await Promise.all([api("/platform/incidents"), api("/platform/abuse")]);
    renderIncidents(incidents, abuse);
  }
  async function loadObservability() {
    const body = $("observabilityBody");
    try {
      const d = await api("/platform/observability?limit=500");
      const statuses = Object.entries(d.counts_by_status || {}).sort().map(([s, n]) => `<span class="tag">HTTP ${esc(s)}: ${fmt.format(asNum(n))}</span>`).join("");
      const paths = (d.top_paths || []).map(p => `<div class="logItem"><b class="mono">${esc(p.path)}</b><span>${fmt.format(asNum(p.count))} request(s)</span></div>`).join("");
      const list = (items, label) => (items || []).length ? `<div class="sectionTitle">${esc(label)}</div>` + items.slice(-10).reverse().map(r => `<div class="event"><b>${esc(r.method || "")} ${esc(r.path || "")} ${statusPill(Number(r.status_code) >= 500 ? "error" : "warn")}</b><span class="mono">${esc(r.organization_id || "")} - ${esc(r.duration_ms)} ms - ${esc(fmtTime(r.created_at, ""))}</span></div>`).join("") : "";
      body.innerHTML = `<div class="riskItem"><b>${fmt.format(asNum(d.window_size))} request(s) in window</b><div>${statuses || "No requests observed."}</div></div>${paths ? `<div class="sectionTitle">Busiest routes</div>${paths}` : ""}${list(d.recent_errors, "Recent server errors")}${list(d.slow_requests, "Slow requests")}`;
    } catch (err) { body.innerHTML = failBox(`Observability unavailable: ${err.message}`, "health"); throw err; }
  }

  // ── Feedback ──────────────────────────────────────────────────────────────
  // opts.limit: a deep link to an older item widens the list past the default 200.
  async function loadFeedback(opts = {}) {
    const query = new URLSearchParams();
    [["status", "feedbackStatus"], ["category", "feedbackCategory"], ["organization_id", "feedbackOrg"]].forEach(([name, id]) => { const value = $(id)?.value || ""; if (value) query.set(name, value); });
    if (opts && opts.limit) query.set("limit", String(opts.limit));
    const body = $("feedbackBody");
    try {
      const d = await api("/platform/feedback" + (query.toString() ? "?" + query : ""));
      const sum = d.summary || {};
      const count = $("feedbackCount");
      if (count) { count.textContent = `${fmt.format(asNum(sum.open))} open`; count.className = `pill ${asNum(sum.open) ? "warn" : "ok"}`; }
      const items = d.items || [];
      const head = `<div class="riskItem"><b>${fmt.format(asNum(sum.total))} total ${sum.average_rating ? `- avg rating ${esc(sum.average_rating)}` : ""}</b><span>${Object.entries(sum.by_category || {}).map(([k, v]) => `${esc(k)} ${fmt.format(asNum(v))}`).join(" - ") || "No feedback yet"}</span></div>`;
      if (body) body.innerHTML = head + (items.map(feedbackRow).join("") || empty("No feedback matches this filter."));
      applyRoleControls();
      return d;
    } catch (err) {
      if (body) body.innerHTML = failBox(`Feedback unavailable: ${err.message || err}`, "feedback");
      throw err;
    }
  }
  function feedbackRow(i) {
    const message = String(i.message || "");
    const shown = message.length > 240 ? `<details class="detailsBlock"><summary>${esc(message.slice(0, 240))}&hellip;</summary><p>${esc(message)}</p></details>` : `<span>${esc(message)}</span>`;
    return `<div class="event" data-record-id="${esc(i.id)}"><b>${esc(i.category)} ${statusPill(i.status || "new")} ${i.rating ? `<span class="pill">${esc(i.rating)}/5</span>` : ""}</b>${shown}<span class="mono">${esc(i.email || i.user_id || "anonymous")} - ${esc(i.organization_id || "org")} - ${esc(fmtTime(i.created_at, ""))}${i.page ? ` - from ${esc(i.page)}` : ""}</span>${i.admin_note ? `<span class="mono warnText">note: ${esc(i.admin_note)}</span>` : ""}<div class="row"><button class="btn secondary small" data-write data-fb="triaged" data-id="${esc(i.id)}" data-note="${esc(i.admin_note || "")}" type="button">Triage</button><button class="btn secondary small" data-write data-fb="resolved" data-id="${esc(i.id)}" data-note="${esc(i.admin_note || "")}" type="button">Resolve</button><button class="btn danger small" data-write data-fb="declined" data-id="${esc(i.id)}" data-note="${esc(i.admin_note || "")}" type="button">Decline</button></div></div>`;
  }
  // A deep link to an item older than the widened list reads that one item instead. Showing it in
  // place is what tells "older than the page loaded" apart from "deleted": a 404 propagates so the
  // caller can say the item no longer exists and mean it.
  async function loadFeedbackItem(id) {
    const item = (await api(`/platform/feedback/${enc(id)}`)).feedback;
    const body = $("feedbackBody");
    if (!body || body.querySelector(`[data-record-id="${CSS.escape(String(item.id))}"]`)) return item;
    body.querySelector(".empty")?.remove();
    const holder = document.createElement("div");
    holder.innerHTML = feedbackRow(item);
    const row = holder.firstElementChild;
    const head = body.querySelector(".riskItem");   // the summary line stays first
    if (head) head.after(row); else body.prepend(row);
    applyRoleControls();
    return item;
  }
  $("feedbackBody")?.addEventListener("click", run(async event => {
    const button = event.target.closest("[data-fb]");
    if (!button) return;
    const values = await openDialog({ title: `Mark feedback #${button.dataset.id} ${button.dataset.fb}`, body: "The note is visible to platform operators only.", fields: [{ name: "admin_note", label: "Admin note", value: button.dataset.note || "" }], submitLabel: "Save", danger: button.dataset.fb === "declined" });
    if (!values) return;
    await api(`/platform/feedback/${enc(button.dataset.id)}`, { method: "PATCH", json: { status: button.dataset.fb, admin_note: values.admin_note } });
    setStatus(`Feedback #${button.dataset.id} marked ${button.dataset.fb}.`, "ok");
    await loadFeedback();
  }));

  // ── Autopatch ─────────────────────────────────────────────────────────────
  async function loadAutopatches() {
    const query = new URLSearchParams({ limit: "100" });
    const status = $("autopatchStatus")?.value || "";
    if (status) query.set("status", status);
    renderAutopatches((await api(`/platform/autopatches?${query}`)).items || []);
  }
  function renderAutopatches(items = []) {
    if (!els.autopatchBody) return;
    if (!items.length) { els.autopatchBody.innerHTML = empty("No autopatch items match."); return; }
    els.autopatchBody.innerHTML = items.map(i => {
      const status = String(i.status || "");
      const actions = [`<button class="btn secondary small" data-ap-view="${esc(i.id)}" type="button">View</button>`];
      if (status === "needs_review") actions.push(`<button class="btn secondary small" data-write data-ap-action="approve" data-id="${esc(i.id)}" type="button">Approve</button>`, `<button class="btn danger small" data-write data-ap-action="reject" data-id="${esc(i.id)}" type="button">Reject</button>`);
      if (status === "approved" || status === "pr_ready") actions.push(`<button class="btn secondary small" data-write data-ap-action="prepare-pr" data-id="${esc(i.id)}" type="button">Prepare PR</button>`);
      return `<div class="event" data-record-id="${esc(i.id)}"><b>#${fmt.format(asNum(i.id))} ${esc(i.title)} ${statusPill(status)}</b><span>${esc(i.issue_type)} - ${esc(i.severity)} - risk ${esc(i.risk_level)}</span><span>${esc(i.diagnosis || "")}</span><div class="row">${actions.join("")}</div>${i.branch_name ? `<span class="mono">Branch: ${esc(i.branch_name)}</span>` : ""}</div>`;
    }).join("");
    applyRoleControls();
  }
  async function showAutopatch(id) {
    const d = await api(`/platform/autopatches/${enc(id)}`);
    const plan = d.patch_plan || {};
    const detail = $("autopatchDetail");
    detail.innerHTML = `<div class="riskItem"><b>#${esc(d.id)} ${esc(d.title)} ${statusPill(d.status)}</b><span>${esc(fmtTime(d.created_at, ""))}</span></div>` +
      kv([["Issue type", d.issue_type], ["Severity", d.severity], ["Risk", d.risk_level], ["Source", d.source], ["Repository", d.repo_full_name], ["Failing check", d.failing_check], ["Plan mode", plan.mode], ["Branch", d.branch_name], ["PR title", d.pr_title]]) +
      (d.diagnosis ? `<div class="event"><b>Diagnosis</b><span>${esc(d.diagnosis)}</span></div>` : "") +
      ((plan.steps || []).length ? `<div class="event"><b>Patch plan</b><ol class="guide">${plan.steps.map(s => `<li>${esc(s)}</li>`).join("")}</ol></div>` : "") +
      ((d.affected_files || []).length ? `<div class="event"><b>Affected files</b><div>${tags(d.affected_files)}</div></div>` : "") +
      (d.logs ? `<details class="detailsBlock"><summary>Logs</summary><pre class="codeBlock">${esc(d.logs)}</pre></details>` : "") +
      (d.pr_body ? `<details class="detailsBlock" open><summary>Prepared PR body</summary><pre class="codeBlock">${esc(d.pr_body)}</pre></details>` : "");
    if (window.matchMedia("(max-width: 900px)").matches) detail.scrollIntoView({ block: "start" });
  }
  els.autopatchBody?.addEventListener("click", run(async event => {
    const view = event.target.closest("[data-ap-view]");
    if (view) { await showAutopatch(view.dataset.apView); return; }
    const button = event.target.closest("[data-ap-action]");
    if (!button) return;
    const { apAction: action, id } = button.dataset;
    if (action === "prepare-pr") {
      const values = await openDialog({ title: `Prepare draft PR for #${id}`, body: "Generates the branch name, PR title and body. A human must open, review and merge the PR.", fields: [{ name: "base_branch", label: "Base branch", value: "main" }], submitLabel: "Prepare", validate: v => v.base_branch.trim() ? "" : "Enter a base branch." });
      if (!values) return;
      await post(`/platform/autopatches/${enc(id)}/prepare-pr`, { base_branch: values.base_branch.trim() });
    } else {
      const values = await openDialog({ title: `${action === "approve" ? "Approve" : "Reject"} autopatch #${id}`, body: action === "approve" ? "Approval allows PR preparation. Nothing is merged or deployed automatically." : "The intake is closed without a PR.", reason: true, submitLabel: action === "approve" ? "Approve" : "Reject", danger: action === "reject" });
      if (!values) return;
      await post(`/platform/autopatches/${enc(id)}/${action}`, { reason: values.reason });
    }
    setStatus(`Autopatch #${id}: ${action} complete.`, "ok");
    await loadAutopatches();
    await showAutopatch(id);
  }));
  $("autopatchForm")?.addEventListener("submit", run(async () => {
    const title = $("apTitle").value.trim();
    if (!title) { note("autopatchStatusText", "Enter a title.", "bad"); $("apTitle").focus(); return; }
    const files = $("apFiles").value.split(/\r?\n/).map(s => s.trim()).filter(Boolean).slice(0, 50);
    const item = await post("/platform/autopatches", { title, issue_type: $("apType").value, severity: $("apSeverity").value, source: "vendor-admin", repo_full_name: $("apRepo").value.trim(), failing_check: $("apCheck").value.trim(), logs: $("apLogs").value, affected_files: files });
    $("autopatchForm").reset();
    note("autopatchStatusText", `Intake #${item.id} created.`, "ok");
    await loadAutopatches();
    await showAutopatch(item.id);
  }));

  // ── Users & access ────────────────────────────────────────────────────────
  async function loadAccess() {
    const body = $("accessBody");
    const query = new URLSearchParams({ limit: "500" });
    const org = $("accessOrg").value;
    const q = $("accessSearch").value.trim();
    if (org) query.set("organization_id", org);
    if (q) query.set("q", q);
    body.innerHTML = skeletonRows(7);
    try {
      const d = await api(`/platform/users?${query}`);
      accessItems = d.items || [];
      if (!accessItems.length) { body.innerHTML = emptyRow(7, q || org ? "No users match this filter." : "No tenant users found."); return; }
      body.innerHTML = accessItems.map((u, index) => {
        const disabled = u.status === "disabled";
        const isMember = (u.sources || []).includes("membership");
        return `<tr data-record-id="${esc(u.user_id)}" data-record-email="${esc(u.email || "")}" data-record-org="${esc(u.organization_id || "")}">
          <td><div class="cellStack"><b>${esc(u.email || u.user_id)}</b><span class="mono muted">${esc(u.user_id)}</span>${u.name ? `<span class="muted">${esc(u.name)}</span>` : ""}</div></td>
          <td class="mono">${esc(u.organization_id || "—")}</td>
          <td>${esc(u.role || "—")}</td>
          <td>${statusPill(u.status)}</td>
          <td>${tags((u.sources || []).map(s => sourceLabels[s] || s))}</td>
          <td class="mono">${esc(fmtTime(u.last_login_at, "Not observed"))}</td>
          <td><div class="inlineActions"><button class="btn secondary small" type="button" data-write data-user-action="role" data-index="${index}">Role</button><button class="btn secondary small" type="button" data-write data-user-action="${disabled ? "reactivate" : "deactivate"}" data-index="${index}">${disabled ? "Reactivate" : "Deactivate"}</button><button class="btn secondary small" type="button" data-write data-user-action="sessions" data-index="${index}">Revoke sessions</button>${isMember ? `<button class="btn danger small" type="button" data-write data-user-action="remove" data-index="${index}">Remove</button>` : ""}</div></td>
        </tr>`;
      }).join("");
      applyRoleControls();
    } catch (err) { body.innerHTML = failRow(7, `Users unavailable: ${err.message}`, "users"); throw err; }
  }
  $("accessFilters")?.addEventListener("submit", run(loadAccess));
  $("accessBody")?.addEventListener("click", run(async event => {
    const button = event.target.closest("[data-user-action]");
    if (!button) return;
    const user = accessItems[Number(button.dataset.index)];
    if (!user) return;
    const who = user.email || user.user_id;
    const base = `/platform/customers/${enc(user.organization_id)}`;
    const action = button.dataset.userAction;
    if (action === "role") {
      const values = await openDialog({ title: `Change role for ${who}`, body: `Organization ${user.organization_id}. Membership roles apply on the next request; sign-in accounts also have their issued tokens revoked so the new role takes effect at the next refresh.`, fields: [{ name: "role", label: "Role", type: "select", value: user.role || "viewer", options: ["viewer", "operator", "admin"].map(r => ({ value: r, label: r })) }], reason: true, submitLabel: "Change role" });
      if (!values) return;
      await api(`${base}/members/${enc(user.user_id)}`, { method: "PATCH", json: { role: values.role, reason: values.reason } });
      setStatus(`${who} is now ${values.role} in ${user.organization_id}.`, "ok");
    } else if (action === "deactivate" || action === "reactivate") {
      const deactivate = action === "deactivate";
      const values = await openDialog({ title: `${deactivate ? "Deactivate" : "Reactivate"} ${who}`, body: deactivate ? "Disables the membership and sign-in account in this organization, deletes refresh sessions, and rejects issued access tokens." : "Re-enables the membership and sign-in account. The user signs in again to get new tokens.", reason: true, submitLabel: deactivate ? "Deactivate" : "Reactivate", danger: deactivate });
      if (!values) return;
      await post(`${base}/users/${enc(user.user_id)}/${action}`, { reason: values.reason, revoke_sessions: true });
      setStatus(`${who} ${deactivate ? "deactivated" : "reactivated"}.`, "ok");
    } else if (action === "sessions") {
      const values = await openDialog({ title: `Revoke sessions for ${who}`, body: "Deletes this user's refresh sessions and rejects every access token issued before now. They can sign in again.", reason: true, submitLabel: "Revoke sessions", danger: true });
      if (!values) return;
      const result = await post("/platform/sessions/revoke", { user_id: user.user_id, reason: values.reason });
      setStatus(`Revoked ${fmt.format(asNum(result.refresh_sessions_revoked))} refresh session(s) for ${who}; earlier access tokens are rejected.`, "ok");
    } else if (action === "remove") {
      const values = await openDialog({ title: `Remove ${who} from ${user.organization_id}`, body: "Deletes the organization membership. A sign-in account, if any, is not deleted; deactivate it separately.", reason: true, submitLabel: "Remove member", danger: true });
      if (!values) return;
      await api(`${base}/members/${enc(user.user_id)}?reason=${enc(values.reason)}`, { method: "DELETE" });
      setStatus(`${who} removed from ${user.organization_id}.`, "ok");
    }
    await loadAccess();
  }));
  $("addMemberForm")?.addEventListener("submit", run(async () => {
    const org = $("memberOrg").value, userId = $("memberUserId").value.trim(), reason = $("memberReason").value.trim();
    if (!org || !userId || reason.length < 3) { note("addMemberStatus", "Choose an organization, enter a user id, and give a reason.", "bad"); return; }
    await post(`/platform/customers/${enc(org)}/members`, { user_id: userId, email: $("memberEmail").value.trim(), display_name: $("memberName").value.trim(), role: $("memberRole").value, reason });
    $("addMemberForm").reset();
    selectOrg(org);
    note("addMemberStatus", `Added ${userId} to ${org}.`, "ok");
    await loadAccess();
  }));
  async function loadInvites() {
    const org = $("inviteOrg").value;
    const body = $("invitesBody");
    if (!org) { body.innerHTML = empty("Choose an organization to see its invitations."); return; }
    try {
      const [d, mail] = await Promise.all([api(`/platform/customers/${enc(org)}/invitations?include_accepted=true`), safeApi("/platform/invitations/email-status")]);
      const items = d.items || [];
      const mailOn = !!(mail.ok && mail.data.email_configured);
      const mailButton = i => mailOn
        ? `<button class="btn secondary small" type="button" data-write data-invite-email="${esc(i.invite_id)}" data-email="${esc(i.email)}">Email the invite</button>`
        : `<span class="formNote">${esc(mail.ok ? "Email isn't configured on this server, so copy the link when you create an invitation." : "Email status unavailable.")}</span>`;
      body.innerHTML = items.length ? items.map(i => `<div class="event"><b>${esc(i.email)} ${statusPill(i.status === "pending" ? "active" : i.status)}</b><span>${esc(i.role)} - invited by ${esc(i.invited_by)} - expires ${esc(fmtTime(i.expires_at))}</span>${i.status === "pending" ? `<div class="row"><button class="btn danger small" type="button" data-write data-invite-revoke="${esc(i.invite_id)}" data-email="${esc(i.email)}">Revoke</button>${mailButton(i)}</div>` : ""}</div>`).join("") : empty("No invitations for this organization.");
      applyRoleControls();
    } catch (err) { body.innerHTML = failBox(`Invitations unavailable: ${err.message}`, "invitations"); throw err; }
  }
  $("inviteOrg")?.addEventListener("change", run(loadInvites));
  $("invitesBtn")?.addEventListener("click", run(loadInvites));
  $("invitesBody")?.addEventListener("click", run(async event => {
    const mailButton = event.target.closest("[data-invite-email]");
    if (mailButton) {
      const values = await openDialog({ title: `Email the invite to ${mailButton.dataset.email}`, body: "Sends the invite link to the invited address only, as a plain email.", reason: true, submitLabel: "Send email" });
      if (!values) return;
      const sent = await post(`/platform/customers/${enc($("inviteOrg").value)}/invitations/${enc(mailButton.dataset.inviteEmail)}/email`, { reason: values.reason });
      setStatus(`Invitation emailed to ${sent.sent_to || mailButton.dataset.email}.`, "ok");
      return;
    }
    const button = event.target.closest("[data-invite-revoke]");
    if (!button) return;
    const org = $("inviteOrg").value;
    const values = await openDialog({ title: `Revoke invitation for ${button.dataset.email}`, body: "The accept link stops working immediately.", reason: true, submitLabel: "Revoke invitation", danger: true });
    if (!values) return;
    await api(`/platform/customers/${enc(org)}/invitations/${enc(button.dataset.inviteRevoke)}?reason=${enc(values.reason)}`, { method: "DELETE" });
    setStatus(`Invitation for ${button.dataset.email} revoked.`, "ok");
    await loadInvites();
  }));
  $("inviteForm")?.addEventListener("submit", run(async () => {
    const org = $("inviteOrg").value, email = $("inviteEmail").value.trim(), reason = $("inviteReason").value.trim();
    if (!org || !email || reason.length < 3) { note("inviteStatus", "Choose an organization, enter an email, and give a reason.", "bad"); return; }
    const result = await post(`/platform/customers/${enc(org)}/invitations`, { email, role: $("inviteRole").value, expires_hours: Number($("inviteHours").value || 72), reason });
    const invitation = result.invitation || {};
    $("inviteEmail").value = ""; $("inviteReason").value = "";
    note("inviteStatus", `Invitation created for ${invitation.email}.`, "ok");
    await loadInvites();
    const link = invitation.invite_link || "";   // the server builds the link; the bare token is never returned
    const shown = openDialog({ title: "Invitation created", body: `Shown once. Send this invite link to ${invitation.email} over a trusted channel${result.email_configured ? ", or use Email the invite in the list below" : " (email isn't configured on this server)"}. They open it, sign in as ${invitation.email}, and accept; it expires ${fmtTime(invitation.expires_at)}.`, secret: link, submitLabel: "Done", noCancel: true });
    text("actionDialogCopy", "Copy invite link");
    await shown;
  }));
  async function loadRateLimits() {
    const org = $("rateOrg").value;
    if (!org) { text("rateNote", "Choose an organization to view its overrides."); return; }
    const d = await api(`/platform/customers/${enc(org)}/rate-limits`);
    $("rateScans").value = d.scans_per_hour ?? "";
    $("rateCalls").value = d.api_calls_per_min ?? "";
    text("rateNote", `${d.note || ""} Last updated: ${fmtTime(d.updated_at, "never")}.`);
  }
  $("rateOrg")?.addEventListener("change", run(loadRateLimits));
  $("rateForm")?.addEventListener("submit", run(async () => {
    const org = $("rateOrg").value, reason = $("rateReason").value.trim();
    if (!org || reason.length < 3) { note("rateStatus", "Choose an organization and give a reason.", "bad"); return; }
    await api(`/platform/customers/${enc(org)}/rate-limits`, { method: "PUT", json: { scans_per_hour: Number($("rateScans").value), api_calls_per_min: Number($("rateCalls").value), reason } });
    $("rateReason").value = "";
    note("rateStatus", `Overrides saved for ${org}.`, "ok");
    await loadRateLimits();
  }));
  async function loadOperators() {
    const body = $("operatorsBody");
    try {
      const d = await api("/platform/operators");
      const errors = (d.configuration_errors || []).map(e => `<div class="notice bad">${esc(e)}</div>`).join("");
      const legacy = `<div class="notice ${d.legacy_key?.enabled ? "warn" : "ok"}"><b>Shared key</b> ${d.legacy_key?.enabled ? `enabled with a ${esc(d.legacy_key.role)} ceiling. Lower MORROW_PLATFORM_ADMIN_KEY_ROLE or remove the key once every administrator has a named credential.` : "disabled."}</div>`;
      const items = (d.items || []).map(o => `<div class="event"><b>${esc(o.name)} <span class="pill">${esc(o.role)}</span></b></div>`).join("");
      body.innerHTML = errors + legacy + (items || empty("No named operators configured. Add entries to MORROW_PLATFORM_OPERATORS."));
    } catch (err) { body.innerHTML = failBox(`Operator roster unavailable: ${err.message}`, "operators"); throw err; }
  }
  $("operatorsBtn")?.addEventListener("click", run(loadOperators));

  // ── API keys ──────────────────────────────────────────────────────────────
  async function loadKeys() {
    const body = $("keysBody");
    const query = new URLSearchParams();
    if ($("keysOrg").value) query.set("organization_id", $("keysOrg").value);
    if ($("keysStatus").value) query.set("status", $("keysStatus").value);
    if (!keyItems.length) body.innerHTML = skeletonRows(8);
    try {
      const d = await api(`/platform/api-keys?${query}`);
      keyItems = d.items || [];
      body.innerHTML = keyItems.length ? keyItems.map((k, index) => `<tr data-record-id="${esc(k.id)}">
        <td><div class="cellStack"><b>${esc(k.name)}</b><span class="mono muted">${esc(k.prefix)}&hellip;</span></div></td>
        <td class="mono">${esc(k.organization_id)}</td>
        <td>${tags(k.scopes)}</td>
        <td><div class="cellStack"><span class="mono">${esc(fmtTime(k.created_at))}</span><span class="muted">${esc(k.created_by || "")}</span></div></td>
        <td class="mono">${esc(fmtTime(k.last_used_at, "Never"))}</td>
        <td class="mono">${esc(fmtTime(k.expires_at, "Never"))}</td>
        <td>${statusPill(k.status)}</td>
        <td><div class="inlineActions">${k.status === "active" ? `<button class="btn secondary small" type="button" data-write data-key-action="rotate" data-index="${index}">Rotate</button>` : ""}${k.status !== "revoked" ? `<button class="btn danger small" type="button" data-write data-key-action="revoke" data-index="${index}">Revoke</button>` : ""}</div></td>
      </tr>`).join("") : emptyRow(8, "No API keys match this filter.");
      applyRoleControls();
    } catch (err) { body.innerHTML = failRow(8, `API keys unavailable: ${err.message}`, "api-keys"); throw err; }
  }
  $("keysFilters")?.addEventListener("submit", run(loadKeys));
  const expiryOptions = [{ value: "30", label: "30 days" }, { value: "90", label: "90 days" }, { value: "180", label: "180 days" }, { value: "365", label: "1 year" }, { value: "", label: "Never" }];
  $("keysBody")?.addEventListener("click", run(async event => {
    const button = event.target.closest("[data-key-action]");
    if (!button) return;
    const item = keyItems[Number(button.dataset.index)];
    if (!item) return;
    if (button.dataset.keyAction === "rotate") {
      const values = await openDialog({ title: `Rotate ${item.name}`, body: `Issues a new secret for ${item.organization_id} with the same scopes. The current key stops working after the grace period.`, fields: [{ name: "grace", label: "Old key keeps working for", type: "select", value: "0", options: [{ value: "0", label: "No grace (revoke now)" }, { value: "3600", label: "1 hour" }, { value: "86400", label: "24 hours" }] }, { name: "expiry", label: "New key expires", type: "select", value: "90", options: expiryOptions }], reason: true, submitLabel: "Rotate key" });
      if (!values) return;
      const result = await post(`/platform/api-keys/${enc(item.id)}/rotate`, { reason: values.reason, grace_seconds: Number(values.grace), expires_in_days: values.expiry ? Number(values.expiry) : null });
      await loadKeys();
      await showSecret("New API key secret", `Shown once. Replace ${item.prefix}… in ${item.organization_id}'s integrations. Use it as Authorization: Bearer <secret>.`, result.secret || "");
    } else {
      const values = await openDialog({ title: `Revoke ${item.name}`, body: `Requests using ${item.prefix}… are rejected immediately on this server and within the cache window on other replicas.`, reason: true, submitLabel: "Revoke key", danger: true });
      if (!values) return;
      await post(`/platform/api-keys/${enc(item.id)}/revoke`, { reason: values.reason });
      setStatus(`${item.name} revoked.`, "ok");
      await loadKeys();
    }
  }));
  $("keyForm")?.addEventListener("submit", run(async () => {
    const org = $("keyOrg").value, name = $("keyName").value.trim(), reason = $("keyReason").value.trim();
    if (!org || !name || reason.length < 3) { note("keyStatus", "Choose an organization, name the key, and give a reason.", "bad"); return; }
    const expiry = $("keyExpiry").value;
    const result = await post(`/platform/customers/${enc(org)}/api-keys`, { name, scopes: [$("keyScope").value], expires_in_days: expiry ? Number(expiry) : null, reason });
    $("keyName").value = ""; $("keyReason").value = "";
    note("keyStatus", `Created ${result.key?.prefix || "key"} for ${org}.`, "ok");
    await loadKeys();
    await showSecret("API key created", `Shown once and never stored. Give it to ${org} through a secret manager. Use it as Authorization: Bearer <secret>.`, result.secret || "");
  }));

  // ── Sessions ──────────────────────────────────────────────────────────────
  async function loadSessions() {
    const body = $("sessionsBody");
    const query = new URLSearchParams({ limit: "500" });
    if ($("sessionsOrg").value) query.set("organization_id", $("sessionsOrg").value);
    if ($("sessionsUser").value.trim()) query.set("user_id", $("sessionsUser").value.trim());
    if (!sessionItems.length) body.innerHTML = skeletonRows(7);
    try {
      const d = await api(`/platform/sessions?${query}`);
      sessionItems = d.items || [];
      const ttl = asNum(d.access_token_ttl_seconds);
      text("sessionsNote", `${d.issuer_enabled ? "Built-in password sign-in sessions." : "Built-in password sign-in is disabled; sessions come from your identity provider and must also be ended there."} Access tokens live ${ttl ? `${fmt.format(Math.round(ttl / 60))} minutes` : "until expiry"}; revoking a user or organization rejects them immediately.`);
      body.innerHTML = !d.available ? emptyRow(7, "Session storage is not initialized on this deployment.") : sessionItems.length ? sessionItems.map((s, index) => `<tr>
        <td class="mono">${esc(s.session_id)}&hellip;</td>
        <td><div class="cellStack"><b>${esc(s.email || s.user_id)}</b><span class="mono muted">${esc(s.user_id)}</span></div></td>
        <td class="mono">${esc(s.org_id || "—")}</td>
        <td>${esc(s.role || "—")} ${s.account_active ? "" : statusPill("disabled")}</td>
        <td class="mono">${esc(fmtTime(s.created_at))}</td>
        <td class="mono">${esc(fmtTime(s.expires_at))}</td>
        <td><div class="inlineActions"><button class="btn secondary small" type="button" data-write data-session-action="session" data-index="${index}">Revoke session</button><button class="btn danger small" type="button" data-write data-session-action="user" data-index="${index}">Revoke user</button></div></td>
      </tr>`).join("") : emptyRow(7, "No active sessions match this filter.");
      const revocations = d.access_revocations || [];
      $("revocationsBody").innerHTML = revocations.length ? revocations.map(r => `<div class="event"><b class="mono">${esc(r.subject)}</b><span>Tokens issued before ${esc(fmtTime(r.revoked_before_iso))} rejected</span><span>${rowText([r.revoked_by, r.reason])}</span></div>`).join("") : empty("No access-token revocations in force.");
      applyRoleControls();
    } catch (err) { body.innerHTML = failRow(7, `Sessions unavailable: ${err.message}`, "sessions"); throw err; }
  }
  $("sessionsFilters")?.addEventListener("submit", run(loadSessions));
  $("sessionsBody")?.addEventListener("click", run(async event => {
    const button = event.target.closest("[data-session-action]");
    if (!button) return;
    const s = sessionItems[Number(button.dataset.index)];
    if (!s) return;
    const whole = button.dataset.sessionAction === "user";
    const values = await openDialog({ title: whole ? `Revoke all access for ${s.email || s.user_id}` : `Revoke session ${s.session_id}…`, body: whole ? "Deletes every refresh session for this user and rejects all access tokens issued before now." : "Stops this session from renewing. Its current access token expires on its own; revoke the user to cut it off now.", reason: true, submitLabel: "Revoke", danger: whole });
    if (!values) return;
    const result = await post("/platform/sessions/revoke", whole ? { user_id: s.user_id, reason: values.reason } : { session_id: s.session_id, reason: values.reason });
    setStatus(`Revoked ${fmt.format(asNum(result.refresh_sessions_revoked))} refresh session(s).${result.access_tokens_revoked_before ? " Earlier access tokens are rejected." : ""}`, "ok");
    await loadSessions();
  }));
  $("revokeForm")?.addEventListener("submit", run(async () => {
    const org = $("revokeOrg").value, user = $("revokeUser").value.trim(), reason = $("revokeReason").value.trim();
    if (!org && !user) { note("revokeStatus", "Choose an organization or enter a user id.", "bad"); return; }
    if (reason.length < 3) { note("revokeStatus", "Give a reason.", "bad"); $("revokeReason").focus(); return; }
    const whole = !user;
    const ok = await openDialog({ title: whole ? `Revoke all access for ${org}` : `Revoke all access for ${user}`, body: whole ? "Every user in this organization is signed out and every access token issued before now is rejected." : "This user's refresh sessions are deleted and earlier access tokens are rejected.", confirmText: whole ? org : "", submitLabel: "Revoke access", danger: true });
    if (!ok) return;
    const result = await post("/platform/sessions/revoke", whole ? { organization_id: org, reason } : { user_id: user, reason });
    $("revokeReason").value = "";
    note("revokeStatus", `Revoked ${fmt.format(asNum(result.refresh_sessions_revoked))} refresh session(s).`, "ok");
    await loadSessions();
  }));

  // ── Data & retention ──────────────────────────────────────────────────────
  async function loadRetentionPolicy() {
    const body = $("retentionPolicyBody");
    try {
      const d = await api("/platform/retention/policy");
      const defaults = d.defaults || {};
      body.innerHTML = kv([["Defaults", Object.entries(defaults).filter(([k]) => k.endsWith("_days")).map(([k, v]) => `${k.replace(/_days$/, "")} ${v}d`).join(", ")], ["Immutable evidence", (d.immutable_evidence || []).join(", ")], ["Batch limit", defaults.limit]]) + (d.notes || []).map(n => `<div class="notice">${esc(n)}</div>`).join("");
    } catch (err) { body.innerHTML = failBox(`Retention policy unavailable: ${err.message}`, "data"); throw err; }
  }
  function retentionPayload(dryRun) {
    const days = id => Number($(id).value || 0) || undefined;
    return { dry_run: dryRun, scans_days: days("retScans"), scan_results_days: days("retScanResults"), validation_jobs_days: days("retValidation"), webhook_events_days: days("retWebhooks"), login_events_days: days("retLogins"), platform_admin_events_days: days("retAdminEvents") };
  }
  function renderRetention(result) {
    const items = result.items || [];
    $("retentionResult").innerHTML = `<div class="riskItem"><b>${result.dry_run ? "Preview" : "Deletion"} ${statusPill(result.dry_run ? "warn" : "ok")}</b><span>${fmt.format(items.reduce((n, i) => n + asNum(i.matched), 0))} matching row(s) - ${fmt.format(items.reduce((n, i) => n + asNum(i.deleted), 0))} deleted</span></div>` + items.map(i => `<div class="event"><b class="mono">${esc(i.table)}</b><span>${i.error ? esc(`Error: ${i.error}`) : `${fmt.format(asNum(i.matched))} older than ${esc(i.days)} days (before ${esc(fmtTime(i.cutoff))}) - ${fmt.format(asNum(i.deleted))} deleted`}</span></div>`).join("");
  }
  $("retentionForm")?.addEventListener("submit", run(async () => {
    lastRetentionPreview = await post("/platform/retention/run", retentionPayload(true));
    renderRetention(lastRetentionPreview);
  }));
  $("retentionRunBtn")?.addEventListener("click", run(async () => {
    const matched = lastRetentionPreview ? (lastRetentionPreview.items || []).reduce((n, i) => n + asNum(i.matched), 0) : null;
    const ok = await openDialog({ title: "Delete aged records", body: matched === null ? "Run a preview first to see how many rows match. This permanently deletes matching operational rows (up to the batch limit per table)." : `The last preview matched ${fmt.format(matched)} row(s). This permanently deletes them (up to the batch limit per table). Audit logs are never deleted.`, confirmText: "DELETE", submitLabel: "Delete rows", danger: true });
    if (!ok) return;
    const result = await post("/platform/retention/run", retentionPayload(false));
    lastRetentionPreview = null;
    renderRetention(result);
    setStatus("Retention run complete.", "ok");
  }));
  async function loadStateCoverage() {
    const body = $("stateCoverageBody");
    try {
      const d = await api("/platform/state/coverage");
      const tables = (d.sqlite_auxiliary_tables || []).slice().sort((a, b) => asNum(b.rows) - asNum(a.rows));
      const withRows = tables.filter(t => asNum(t.rows) > 0);
      body.innerHTML = `<div class="riskItem"><b>${fmt.format(asNum(d.sqlite_auxiliary_table_count))} SQLite-only table(s) ${statusPill(withRows.length ? "warn" : "ok")}</b><span>${fmt.format(withRows.length)} holding rows - Postgres mode ${d.postgres_mode ? "on" : "off"} - ${fmt.format(asNum(d.postgres_archive_records))} archived record(s)</span><span>${esc(d.scale_rule || "")}</span></div>` + (withRows.slice(0, 40).map(t => `<div class="logItem"><b class="mono">${esc(t.table)}</b><span>${fmt.format(asNum(t.rows))} row(s)</span></div>`).join("") || empty("No auxiliary SQLite table holds rows."));
    } catch (err) { body.innerHTML = failBox(`State coverage unavailable: ${err.message}`, "data"); throw err; }
  }
  async function migrateState(dryRun) {
    if (!dryRun) {
      const ok = await openDialog({ title: "Migrate auxiliary state to Postgres", body: "Copies SQLite-only auxiliary rows into Postgres archive records. Run a preview first and take a database backup.", confirmText: "MIGRATE", submitLabel: "Migrate", danger: true });
      if (!ok) return;
    }
    const target = $("migrateResult");
    try {
      const result = await post("/platform/state/migrate", { dry_run: dryRun });
      target.innerHTML = `<div class="riskItem"><b>${dryRun ? "Migration preview" : "Migration"} ${statusPill("ok")}</b><span>${fmt.format(asNum(result.copied))} row(s) copied</span></div>` + Object.entries(result.tables || {}).map(([t, v]) => `<div class="logItem"><b class="mono">${esc(t)}</b><span>${fmt.format(asNum(v.matched))} matched - ${fmt.format(asNum(v.copied))} copied</span></div>`).join("");
      if (!dryRun) await loadStateCoverage();
    } catch (err) { target.innerHTML = `<div class="notice warn">${esc(err.message)}</div>`; }
  }
  async function loadLogStorage() {
    const body = $("logStorageBody");
    try {
      const d = await api("/platform/logging/health");
      const writes = Object.entries(d.writes || {}).map(([kind, w]) => `<div class="logItem"><b>${esc(kind)}</b><span>last success ${esc(fmtTime(w.last_success_at, "never"))}</span><span>${fmt.format(asNum(w.failed_writes))} failed write(s)${w.last_failure_at ? ` - last failure ${esc(fmtTime(w.last_failure_at))}` : ""}</span></div>`).join("");
      body.innerHTML = `<div class="riskItem"><b>Log storage ${statusPill(d.status)}</b><span>${esc(d.scope || "")}</span></div>` + kv([["Backend", d.backend], ["Readable", d.readable ? "yes" : "no"], ["Authentication retention", `${d.auth_retention_days ?? "unknown"} days`], ["Traffic retention", `${d.traffic_retention_days ?? "unknown"} days`], ["Traffic archive", d.traffic_persistence_enabled ? "enabled" : "disabled"]]) + writes;
    } catch (err) { body.innerHTML = failBox(`Log storage unavailable: ${err.message}`, "health"); throw err; }
  }
  $("exportForm")?.addEventListener("submit", run(async () => {
    const org = $("exportOrg").value;
    if (!org) { note("exportStatus", "Choose an organization.", "bad"); return; }
    note("exportStatus", "Preparing export...");
    await download(`/platform/customers/${enc(org)}/export`, `pq-gdpr-export-${org}.json`);
    note("exportStatus", `GDPR export for ${org} downloaded.`, "ok");
  }));
  $("exportAuditPackageBtn")?.addEventListener("click", run(async () => {
    const org = $("exportOrg").value;
    if (!org) { note("exportStatus", "Choose an organization.", "bad"); return; }
    note("exportStatus", "Building audit package...");
    await download(`/platform/customers/${enc(org)}/audit-package`, `pq-audit-package-${org}.zip`);
    note("exportStatus", `Audit package for ${org} downloaded.`, "ok");
  }));

  // ── Announcements & maintenance ───────────────────────────────────────────
  function renderMaintenanceState(state) {
    const on = !!state.enabled;
    const badge = $("maintenanceStateBadge");
    if (badge) { badge.textContent = on ? "on" : "off"; badge.className = `pill ${on ? "bad" : "ok"}`; }
    const pill = $("maintenancePill");
    if (pill) pill.hidden = !on;
    return `<div class="notice ${on ? "bad" : "ok"}"><b>Maintenance ${on ? "is on" : "is off"}.</b> ${on ? esc(state.message || "") : "Customer writes are accepted."}${on && state.ends_at ? ` Expected end: ${esc(fmtTime(state.ends_at))}.` : ""}${state.overdue ? " The expected end has passed; writes stay paused until you turn it off." : ""}${state.updated_at ? ` Last changed ${esc(fmtTime(state.updated_at))}${state.updated_by ? ` by ${esc(state.updated_by)}` : ""}.` : ""}</div>`;
  }
  async function loadMaintenance() {
    const body = $("maintenanceBody");
    try {
      const d = await api("/platform/maintenance");
      body.innerHTML = renderMaintenanceState(d);
      if (d.enabled) { $("maintenanceMessage").value = d.message || ""; $("maintenanceEnds").value = toLocalInput(d.ends_at); }
      return d;
    } catch (err) { body.innerHTML = failBox(`Maintenance state unavailable: ${err.message}`, "maintenance"); throw err; }
  }
  async function loadMaintenanceSummary() {
    const body = $("maintenanceSummary");
    const [maintenance, announcements] = await Promise.all([safeApi("/platform/maintenance"), safeApi("/platform/announcements")]);
    if (!maintenance.ok && !announcements.ok) { body.innerHTML = empty(`Maintenance state unavailable: ${maintenance.error}`); return; }
    const active = (announcements.data?.items || []).filter(a => a.state === "active");
    body.innerHTML = (maintenance.ok ? renderMaintenanceState(maintenance.data) : "") + (active.length ? active.slice(0, 3).map(a => `<div class="event"><b>${esc(a.title)} ${statusPill(a.severity === "critical" ? "critical" : a.severity === "warn" ? "warn" : "ok")}</b><span>${esc(a.audience === "orgs" ? `${a.organization_ids.length} organization(s)` : "All customers")}${a.ends_at ? ` - until ${esc(fmtTime(a.ends_at))}` : ""}</span></div>`).join("") : empty("No active announcements."));
  }
  $("maintenanceForm")?.addEventListener("submit", run(async () => {
    const reason = $("maintenanceReason").value.trim();
    if (reason.length < 3) { note("maintenanceStatus", "Give a reason.", "bad"); $("maintenanceReason").focus(); return; }
    const message = $("maintenanceMessage").value.trim();
    const ok = await openDialog({ title: "Turn maintenance mode on", body: `Every customer write (non-GET request) will answer 503${message ? ` with: "${message}"` : " with the default maintenance message"}. Sign-in, reads, platform administration, health and status keep working.`, submitLabel: "Turn on", danger: true });
    if (!ok) return;
    const state = await api("/platform/maintenance", { method: "PUT", json: { enabled: true, message, ends_at: fromLocalInput($("maintenanceEnds").value), reason } });
    $("maintenanceReason").value = "";
    $("maintenanceBody").innerHTML = renderMaintenanceState(state);
    note("maintenanceStatus", "Maintenance mode is on.", "ok");
    loadMaintenanceSummary().catch(() => {});
  }));
  $("maintenanceOffBtn")?.addEventListener("click", run(async () => {
    const reason = $("maintenanceReason").value.trim();
    if (reason.length < 3) { note("maintenanceStatus", "Give a reason for turning maintenance off.", "bad"); $("maintenanceReason").focus(); return; }
    const state = await api("/platform/maintenance", { method: "PUT", json: { enabled: false, reason } });
    $("maintenanceReason").value = "";
    $("maintenanceBody").innerHTML = renderMaintenanceState(state);
    note("maintenanceStatus", "Maintenance mode is off. Customer writes are accepted.", "ok");
    loadMaintenanceSummary().catch(() => {});
  }));
  async function loadAnnouncements() {
    const body = $("announcementsBody");
    try {
      const d = await api("/platform/announcements");
      announcementItems = d.items || [];
      body.innerHTML = announcementItems.length ? announcementItems.map((a, index) => `<div class="event" data-record-id="${esc(a.id)}"><b>${esc(a.title)} ${statusPill(a.state === "active" ? "active" : a.state === "expired" ? "rejected" : "warn")} <span class="pill">${esc(a.severity)}</span></b>${a.body ? `<span>${esc(a.body)}</span>` : ""}<span>${esc(a.audience === "orgs" ? `Organizations: ${a.organization_ids.join(", ")}` : "All customers")} - ${esc(a.starts_at ? `from ${fmtTime(a.starts_at)}` : "from publication")}${a.ends_at ? ` until ${esc(fmtTime(a.ends_at))}` : ""}</span><span class="mono">Updated ${esc(fmtTime(a.updated_at))} by ${esc(a.updated_by || a.created_by || "unknown")}</span><div class="row"><button class="btn secondary small" type="button" data-write data-ann-action="edit" data-index="${index}">Edit</button><button class="btn danger small" type="button" data-write data-ann-action="delete" data-index="${index}">Delete</button></div></div>`).join("") : empty("No announcements yet.");
      applyRoleControls();
    } catch (err) { body.innerHTML = failBox(`Announcements unavailable: ${err.message}`, "announcements"); throw err; }
  }
  function resetAnnouncementForm() {
    $("announcementForm").reset();
    $("annId").value = "";
    $("annOrgsField").hidden = true;
    text("announcementFormTitle", "New announcement");
    text("saveAnnouncementBtn", "Publish announcement");
  }
  $("annAudience")?.addEventListener("change", () => { $("annOrgsField").hidden = $("annAudience").value !== "orgs"; });
  $("resetAnnouncementBtn")?.addEventListener("click", () => { resetAnnouncementForm(); note("announcementStatus", ""); });
  $("announcementsBtn")?.addEventListener("click", run(loadAnnouncements));
  $("announcementsBody")?.addEventListener("click", run(async event => {
    const button = event.target.closest("[data-ann-action]");
    if (!button) return;
    const item = announcementItems[Number(button.dataset.index)];
    if (!item) return;
    if (button.dataset.annAction === "edit") {
      $("annId").value = item.id;
      $("annTitle").value = item.title || "";
      $("annBody").value = item.body || "";
      $("annSeverity").value = item.severity || "info";
      $("annAudience").value = item.audience || "all";
      $("annOrgs").value = (item.organization_ids || []).join(", ");
      $("annOrgsField").hidden = item.audience !== "orgs";
      $("annStarts").value = toLocalInput(item.starts_at);
      $("annEnds").value = toLocalInput(item.ends_at);
      text("announcementFormTitle", `Edit announcement #${item.id}`);
      text("saveAnnouncementBtn", "Save changes");
      $("annTitle").focus();
      $("announcementForm").scrollIntoView({ block: "center" });
      return;
    }
    const values = await openDialog({ title: `Delete "${item.title}"`, body: "Customers stop seeing it at their next page load.", reason: true, submitLabel: "Delete", danger: true });
    if (!values) return;
    await api(`/platform/announcements/${enc(item.id)}?reason=${enc(values.reason)}`, { method: "DELETE" });
    setStatus(`Announcement "${item.title}" deleted.`, "ok");
    await loadAnnouncements();
    loadMaintenanceSummary().catch(() => {});
  }));
  $("announcementForm")?.addEventListener("submit", run(async () => {
    const title = $("annTitle").value.trim();
    if (!title) { note("announcementStatus", "Enter a title.", "bad"); $("annTitle").focus(); return; }
    const audience = $("annAudience").value;
    const orgs = $("annOrgs").value.split(",").map(s => s.trim()).filter(Boolean);
    if (audience === "orgs" && !orgs.length) { note("announcementStatus", "List at least one organization id.", "bad"); $("annOrgs").focus(); return; }
    const payload = { title, body: $("annBody").value.trim(), severity: $("annSeverity").value, audience, organization_ids: audience === "orgs" ? orgs : [], starts_at: fromLocalInput($("annStarts").value), ends_at: fromLocalInput($("annEnds").value) };
    const id = $("annId").value;
    await api(id ? `/platform/announcements/${enc(id)}` : "/platform/announcements", { method: id ? "PUT" : "POST", json: payload });
    note("announcementStatus", id ? "Announcement updated." : "Announcement published.", "ok");
    resetAnnouncementForm();
    await loadAnnouncements();
    loadMaintenanceSummary().catch(() => {});
  }));

  // ── Audit ─────────────────────────────────────────────────────────────────
  function eventsQuery(offset) {
    const query = new URLSearchParams();
    [["q", "eventsQuery"], ["organization_id", "eventsOrg"], ["action", "eventsAction"], ["actor", "eventsActor"], ["since", "eventsSince"], ["until", "eventsUntil"]].forEach(([name, id]) => { const value = ($(id)?.value || "").trim(); if (value) query.set(name, value); });
    if (offset !== null) { query.set("limit", "50"); query.set("offset", String(offset)); }
    return query;
  }
  function renderEventRows(items, target) {
    if (!target) return;
    if (!items?.length) { target.innerHTML = empty("No admin events match."); return; }
    target.innerHTML = items.map(i => {
      const details = i.details || i.details_json || {};
      const operator = i.actor_id || details.operator?.actor_id || "platform-admin";
      const operatorRole = i.operator_role || details.operator?.actor_role || "";
      const extra = Object.fromEntries(Object.entries(details).filter(([k]) => k !== "operator"));
      return `<div class="event"><b>${esc(i.action || "event")}</b><span class="mono">${esc(operator)}${operatorRole ? ` (${esc(operatorRole)})` : ""} · ${esc(i.organization_id || "platform")} · ${esc(fmtTime(i.created_at, ""))}</span><span>${esc(i.reason || "No reason recorded")}</span>${Object.keys(extra).length ? `<details class="detailsBlock"><summary>Details</summary><p class="mono">${esc(JSON.stringify(extra, null, 2))}</p></details>` : ""}</div>`;
    }).join("");
  }
  function renderEventsResult(d) {
    const items = d.items || [];
    const offset = asNum(d.offset);
    const total = asNum(d.total);
    renderEventRows(items, els.eventsBody);
    text("eventsPageInfo", total ? `${fmt.format(offset + 1)}-${fmt.format(offset + items.length)} of ${fmt.format(total)}` : "No results");
    const prev = $("eventsPrev"), next = $("eventsNext");
    prev.disabled = offset <= 0; prev.dataset.offset = String(Math.max(0, offset - 50));
    next.disabled = d.next_offset == null; next.dataset.offset = String(d.next_offset ?? 0);
  }
  async function loadEvents(offset = 0) {
    try { const d = await api(`/platform/admin-events/search?${eventsQuery(offset)}`); renderEventsResult(d); return d; }
    catch (err) { els.eventsBody.innerHTML = failBox(`Audit trail unavailable: ${err.message}`, "audit"); throw err; }
  }
  $("eventsFilters")?.addEventListener("submit", run(() => loadEvents(0)));
  $("eventsPrev")?.addEventListener("click", run(() => loadEvents(Number($("eventsPrev").dataset.offset || 0))));
  $("eventsNext")?.addEventListener("click", run(() => loadEvents(Number($("eventsNext").dataset.offset || 0))));
  $("eventsExportBtn")?.addEventListener("click", run(async () => { await download(`/platform/admin-events/export.csv?${eventsQuery(null)}`, "morrow-platform-admin-events.csv"); setStatus("Admin audit export downloaded.", "ok"); }));
  function tenantAuditQuery() {
    const query = new URLSearchParams();
    [["actor_id", "tenantAuditActor"], ["action", "tenantAuditAction"], ["decision", "tenantAuditDecision"]].forEach(([name, id]) => { const value = ($(id)?.value || "").trim(); if (value) query.set(name, value); });
    return query;
  }
  $("tenantAuditFilters")?.addEventListener("submit", run(async () => {
    const org = $("tenantAuditOrg").value;
    const body = $("tenantAuditBody");
    if (!org) { body.innerHTML = emptyRow(6, "Choose an organization to load its audit log."); return; }
    const query = tenantAuditQuery(); query.set("limit", "500");
    body.innerHTML = skeletonRows(6);
    try {
      const d = await api(`/platform/customers/${enc(org)}/audit-logs?${query}`);
      const items = d.items || [];
      body.innerHTML = items.length ? items.map(r => `<tr><td class="mono">${esc(fmtTime(r.created_at))}</td><td><div class="cellStack"><b>${esc(r.actor_id)}</b><span class="muted">${esc(r.actor_role || "")}</span></div></td><td class="mono">${esc(r.action)}</td><td class="mono">${esc([r.resource_type, r.resource_id].filter(Boolean).join(":"))}</td><td>${statusPill(r.decision || "allow")}</td><td>${esc(r.reason || "")}</td></tr>`).join("") : emptyRow(6, "No audit entries match.");
    } catch (err) { body.innerHTML = failRow(6, `Audit log unavailable: ${err.message}`, "tenant-audit"); throw err; }
  }));
  $("tenantAuditExportBtn")?.addEventListener("click", run(async () => {
    const org = $("tenantAuditOrg").value;
    if (!org) { setStatus("Choose an organization in the tenant audit log first.", "bad"); return; }
    await download(`/platform/customers/${enc(org)}/audit-logs/export.csv?${tenantAuditQuery()}`, `pq-audit-${org}.csv`);
    setStatus(`Audit log for ${org} downloaded.`, "ok");
  }));

  // ── Portal load ───────────────────────────────────────────────────────────
  function loadExtras() {
    return Promise.allSettled([loadFeedback(), loadGate(), loadTraffic()]);
  }
  async function loadPortal() {
    if (loading) return;
    loading = true;
    els.load.disabled = true; els.reloadAll.disabled = true;
    if (!customers.length && els.customersBody) els.customersBody.innerHTML = skeletonRows(8, 5);
    try {
      setStatus("Loading platform admin data..."); setApi("loading", "warn");
      const who = await safeApi("/platform/whoami", { noRole: true });
      if (!who.ok && [401, 403].includes(who.status) && (sessionAuth.active || /key/i.test(who.error))) throw new Error(who.error);
      if (who.ok && who.data.csrf_token) sessionAuth.csrf = who.data.csrf_token;
      applyIdentity(who.ok ? who.data : null);
      document.dispatchEvent(new CustomEvent("admin:identity", { detail: who.ok ? who.data : null }));
      // A named operator key that still needs its authenticator: every other route answers 401 until
      // it is enrolled and verified, so hand over to the authenticator step instead of failing the load.
      const mfa = who.ok ? who.data.mfa : null;
      if (!sessionAuth.active && mfa && mfa.can_enrol && !mfa.elevated && (mfa.enrolled || mfa.required) && window.AdminAuth?.keyChallenge) {
        window.AdminAuth.keyChallenge(who.data);
        setStatus("Confirm with your authenticator app to continue.", "warn");
        return;
      }
      const autopatchQuery = new URLSearchParams({ limit: "100" });
      if ($("autopatchStatus")?.value) autopatchQuery.set("status", $("autopatchStatus").value);
      const paths = ["/platform/metrics", "/platform/customers", authEventsPath(), "/platform/health", "/platform/readiness", `/platform/admin-events/search?${eventsQuery(0)}`, `/platform/autopatches?${autopatchQuery}`, "/platform/security-truth?limit=80", "/platform/incidents", "/platform/abuse", "/platform/admin-mode"];
      const results = await Promise.all(paths.map(p => safeApi(p)));
      const [metricsR, custR, logsR, healthR, readinessR, eventsR, autopatchesR, securityTruthR, incidentsR, abuseR, adminModeR] = results;
      if (!metricsR.ok && !custR.ok) throw new Error(metricsR.error || custR.error || "Platform admin API blocked.");
      const firstConnect = !connected;
      connected = true;
      const metrics = metricsR.data || {};
      lastMetrics = metrics;
      const cust = custR.data || {};
      customers = cust.customers || [];
      metric("mCustomers", metrics.customers_total ?? cust.summary?.total_customers);
      metric("mActive", metrics.customers_active_7d ?? cust.summary?.active_last_7_days);
      metric("mScans", metrics.total_scans ?? cust.summary?.total_scans_all_time);
      metric("mAssets", metrics.total_assets ?? cust.summary?.total_assets);
      metric("mRems", metrics.total_remediations ?? cust.summary?.total_remediations);
      metric("mLogins", metrics.logins_last_24h);
      if (metrics.logins_last_7d != null) text("mLoginsDetail", `${fmt.format(asNum(metrics.logins_last_7d))} in 7 days`);
      text("generatedAt", fmtTime(metrics.generated_at, "generated"));
      custR.ok ? (renderPlanFilter(), renderCustomers()) : (els.customersBody.innerHTML = failRow(8, `Customers unavailable: ${custR.error}`, "portal"));
      populateOrgSelects();
      logsR.ok ? renderAuthHistory(logsR.data || {}) : (els.logsBody.innerHTML = empty(`Authentication history unavailable: ${logsR.error}`));
      if (!logsR.ok) text("loggingHealth", "Storage unavailable; retained history is unknown, not empty.");
      if (metricsR.ok) renderRisk(metrics.churn_risk || [], metrics.customers_never_active);
      else { text("mAtRisk", "--"); text("riskCount", "unavailable"); els.riskBody.innerHTML = empty(`Activation risk unavailable: ${metricsR.error}`); }
      if (metricsR.ok || custR.ok) renderPlans(metrics.plan_breakdown || cust.summary?.plan_breakdown || {});
      if (!healthR.ok) text("mHealthState", "Unknown");
      healthR.ok ? renderHealth(healthR.data) : (els.healthBody.innerHTML = empty(`Health unavailable: ${healthR.error}`));
      readinessR.ok ? renderReadiness(readinessR.data) : (els.readinessBody.innerHTML = empty(`Readiness unavailable: ${readinessR.error}`));
      if (healthR.ok && readinessR.ok && securityTruthR.ok && metricsR.ok) renderTelemetry(metrics, healthR.data, readinessR.data, securityTruthR.data);
      else { text("mOpenAlerts", "--"); els.telemetryBody.innerHTML = empty("Alert summary unavailable: one or more source checks failed."); }
      incidentsR.ok && abuseR.ok ? renderIncidents(incidentsR.data, abuseR.data) : (els.incidentsBody.innerHTML = empty("Incident sources unavailable."));
      eventsR.ok ? renderEventsResult(eventsR.data) : (els.eventsBody.innerHTML = empty(`Audit unavailable: ${eventsR.error}`));
      autopatchesR.ok ? renderAutopatches(autopatchesR.data?.items || []) : (els.autopatchBody.innerHTML = empty(`Autopatch unavailable: ${autopatchesR.error}`));
      securityTruthR.ok ? renderSecurityTruth(securityTruthR.data) : (els.securityTruthBody.innerHTML = empty(`Security findings unavailable: ${securityTruthR.error}`));
      adminModeR.ok ? renderAdminMode(adminModeR.data) : (els.adminModeBody.textContent = `Admin mode unavailable: ${adminModeR.error}`);
      const extras = await loadExtras();
      const failed = results.filter(result => !result.ok).length + extras.filter(result => result.status === "rejected").length;
      setApi(failed ? "API partially available" : "API connected", failed ? "warn" : "ok");
      setStatus(failed ? `Loaded available data. ${failed} source(s) failed; inspect affected panels.` : "Platform snapshot loaded.", failed ? "warn" : "ok");
      text("snapshotAt", `Refreshed ${new Date().toLocaleTimeString()}`);
      loadMaintenanceSummary().catch(() => {});
      if (firstConnect && els.rememberCheck?.checked && !remembered()) rememberCredential();
      document.dispatchEvent(new CustomEvent(firstConnect ? "admin:connected" : "admin:snapshot", { detail: { failed } }));
    } finally {
      loading = false;
      els.load.disabled = false; els.reloadAll.disabled = false;
      applyRoleControls();
    }
  }

  // ── Customer drawer ───────────────────────────────────────────────────────
  function renderFeatureFlags(items = []) {
    const el = $("detailFeatureFlags");
    if (!el) return;
    el.innerHTML = items.length ? items.map(i => `<div class="event"><b>${esc(i.flag_key)} ${statusPill(i.enabled ? "active" : "disabled")}</b><span>${esc(i.reason || "")}</span><span class="mono">${esc(fmtTime(i.updated_at, ""))}</span><div class="row"><button class="btn danger small" type="button" data-write data-flag-delete="${esc(i.flag_key)}">Remove override</button></div></div>`).join("") : empty("No feature flags configured for this customer.");
    applyRoleControls();
  }
  async function openCustomer(org, section = "") {
    const version = ++detailVersion;
    const data = await api(`/platform/customers/${enc(org)}`);
    if (version !== detailVersion) return;
    selectedOrg = org;
    const c = data.customer || {};
    text("detailName", c.name || org); text("detailOrgId", org);
    $("detailRisk").innerHTML = riskPill(c.risk_score || 0); text("detailScans", fmt.format(asNum(c.scan_count))); text("detailAssets", fmt.format(asNum(c.asset_count)));
    $("detailPlan").value = c.plan_type || "starter"; $("detailStatus").value = c.subscription_status || "active"; $("detailStage").value = c.lifecycle_stage || ""; $("detailRenewal").value = c.renewal_at || ""; $("detailOwner").value = c.account_owner || ""; $("detailNotes").value = c.internal_notes || "";
    $("detailNameInput").value = c.name || ""; $("detailReason").value = ""; text("detailStatusText", "");
    renderLogs(data.recent_logins || [], $("detailLogins")); renderEventRows(data.admin_events || [], $("detailEvents"));
    if (!(data.admin_events || []).length) $("detailEvents").innerHTML = empty("No admin events for this customer yet.");
    const checklist = data.onboarding_checklist?.checks || [];
    $("detailOnboarding").innerHTML = checklist.length ? checklist.map(i => `<div class="event"><b>${esc(i.label)} ${statusPill(i.status === "pass" ? "pass" : i.status === "warn" ? "warn" : "blocked")}</b><span>${esc(i.detail || "")}</span></div>`).join("") : empty("No onboarding checklist returned.");
    renderFeatureFlags(data.feature_flags || []);
    const rems = Object.entries(data.remediation_status || {});
    $("detailRemediations").innerHTML = rems.length ? rems.map(([s, n]) => `<div class="riskItem"><b>${esc(s)}</b><span>${fmt.format(asNum(n))} remediation(s)</span></div>`).join("") : empty("No remediation status.");
    $("detailScansList").innerHTML = (data.recent_scans || []).length ? data.recent_scans.map(s => `<div class="riskItem"><b>${esc(s.status || "scan")}</b><span class="mono">${esc(s.id || "")}</span><span>${esc(fmtTime(s.created_at, ""))}</span></div>`).join("") : empty("No recent scans.");
    $("detailUsers").innerHTML = empty("Loading users...");
    $("detailKeys").innerHTML = "";
    $("detailRate").innerHTML = "";
    if (!els.drawer.classList.contains("open")) returnFocus = document.activeElement;
    els.drawer.classList.add("open");
    els.drawer.setAttribute("aria-hidden", "false");
    setInert();
    els.closeDrawer.focus();
    applyRoleControls();
    if (section && $(section)) $(section).scrollIntoView({ block: "start" });
    else els.drawer.querySelector(".panel").scrollTop = 0;
    loadDrawerExtras(org, version).catch(() => {});
  }
  // limit_source from services/org_rate_limits.describe: override | default | none.
  function rateEnforcement(d) {
    if (d.enforced === false && d.limit_source && d.limit_source !== "none") return `off (MORROW_ORG_RATE_LIMITS_ENABLED=0); would be ${d.limit_source_label || d.limit_source}`;
    if (!d.enforced) return "not limited per organization (no override and no platform default)";
    const source = d.limit_source || (d.override ? "override" : "default");
    const label = d.limit_source_label || { override: "operator override", default: "platform default" }[source] || source;
    return `enforced (${label})`;
  }
  async function loadDrawerExtras(org, version) {
    const base = `/platform/customers/${enc(org)}`;
    const [users, keys, rate, catalog] = await Promise.all([safeApi(`${base}/users`), safeApi(`${base}/api-keys`), safeApi(`${base}/rate-limits`), safeApi("/platform/feature-flags/catalog")]);
    if (version !== detailVersion) return;
    if (users.ok) {
      const items = users.data.items || [];
      $("detailUsers").innerHTML = `<div class="riskItem"><b>${fmt.format(items.length)} user(s)</b><span>${fmt.format(items.filter(u => u.status === "disabled").length)} disabled</span></div>` + items.slice(0, 8).map(u => `<div class="logItem"><b>${esc(u.email || u.user_id)}</b><span>${esc(u.role || "—")} ${statusPill(u.status)}</span><span class="mono">${esc(fmtTime(u.last_login_at, "Not observed"))}</span></div>`).join("");
    } else $("detailUsers").innerHTML = empty(`Users unavailable: ${users.error}`);
    if (keys.ok) {
      const items = keys.data.items || [];
      const active = items.filter(k => k.status === "active");
      $("detailKeys").innerHTML = `<div class="riskItem"><b>${fmt.format(active.length)} active API key(s)</b><span>${fmt.format(items.length - active.length)} expired or revoked</span></div>` + active.slice(0, 5).map(k => `<div class="logItem"><b>${esc(k.name)}</b><span class="mono">${esc(k.prefix)}&hellip;</span><span>${tags(k.scopes)}</span></div>`).join("");
    }
    if (rate.ok) $("detailRate").innerHTML = kv([["Scans per hour", rate.data.scans_per_hour], ["API calls per minute", rate.data.api_calls_per_min], ["Enforcement", rateEnforcement(rate.data)]]);
    if (catalog.ok) {
      $("flagCatalog").innerHTML = (catalog.data.items || []).map(f => `<option value="${esc(f.flag_key)}">${esc(f.label)}</option>`).join("");
      text("flagSemantics", `${catalog.data.semantics || ""} Known flags: ${(catalog.data.items || []).map(f => f.flag_key).join(", ")}.`);
    }
  }
  function closeCustomer() {
    detailVersion++;
    els.drawer.classList.remove("open");
    els.drawer.setAttribute("aria-hidden", "true");
    setInert();
    if (returnFocus?.isConnected) returnFocus.focus();
    else $("adminViewTitle").focus();
  }
  async function refreshCustomer(org, version) {
    await loadPortal();
    if (version === detailVersion && els.drawer.classList.contains("open")) await openCustomer(org);
  }
  async function saveSelected() {
    if (!selectedOrg) return;
    const org = selectedOrg, version = detailVersion;
    els.saveCustomer.disabled = true;
    try {
      text("detailStatusText", "Saving...");
      await api(`/platform/customers/${enc(org)}`, { method: "PATCH", json: { plan_type: $("detailPlan").value, subscription_status: $("detailStatus").value, lifecycle_stage: $("detailStage").value, renewal_at: $("detailRenewal").value, account_owner: $("detailOwner").value, internal_notes: $("detailNotes").value } });
      if (version === detailVersion) text("detailStatusText", "Saved.");
      await refreshCustomer(org, version);
    } finally { applyRoleControls(); }
  }
  function lifecycleReason() {
    const reason = ($("detailReason").value || "").trim();
    if (reason.length < 3) {
      text("detailStatusText", "Enter a reason (at least 3 characters) before changing this customer's lifecycle.");
      $("detailReason").focus();
      return "";
    }
    return reason;
  }
  async function actionSelected(action) {
    if (!selectedOrg) return;
    const org = selectedOrg, version = detailVersion;
    const reason = lifecycleReason();
    if (!reason) return;
    const suspend = action === "suspend";
    const ok = await openDialog({ title: `${suspend ? "Suspend" : "Resume"} ${org}?`, body: suspend ? "Customer requests for this organization are refused until it is resumed. Platform administration is unaffected." : "Customer requests for this organization are accepted again.", submitLabel: suspend ? "Suspend" : "Resume", danger: suspend });
    if (!ok) return;
    await post(`/platform/customers/${enc(org)}/${action}`, { reason });
    setStatus(`${org} ${suspend ? "suspended" : "resumed"}.`, "ok");
    await refreshCustomer(org, version);
  }
  $("renameCustomerBtn")?.addEventListener("click", run(async () => {
    if (!selectedOrg) return;
    const org = selectedOrg, version = detailVersion;
    const name = $("detailNameInput").value.trim();
    if (!name) { text("detailStatusText", "Enter a display name."); $("detailNameInput").focus(); return; }
    const reason = lifecycleReason();
    if (!reason) return;
    await post(`/platform/customers/${enc(org)}/rename`, { name, reason });
    setStatus(`${org} renamed to ${name}.`, "ok");
    await refreshCustomer(org, version);
  }));
  $("archiveBtn")?.addEventListener("click", run(async () => {
    if (!selectedOrg) return;
    const org = selectedOrg, version = detailVersion;
    const reason = lifecycleReason();
    if (!reason) return;
    const ok = await openDialog({ title: `Archive ${org}?`, body: "The organization is marked archived. Its data is kept; purge separately if the contract requires deletion.", submitLabel: "Archive", danger: true });
    if (!ok) return;
    await post(`/platform/customers/${enc(org)}/archive`, { reason });
    setStatus(`${org} archived.`, "ok");
    await refreshCustomer(org, version);
  }));
  $("purgeBtn")?.addEventListener("click", run(async () => {
    if (!selectedOrg) return;
    const org = selectedOrg;
    const reason = lifecycleReason();
    if (!reason) return;
    const ok = await openDialog({ title: `Permanently purge ${org}`, body: "Deletes the organization and its scans, assets, remediations, memberships, credentials and tenant audit log, revokes its API keys, and signs out its users. This cannot be undone. Download the GDPR export first if you need a copy.", confirmText: org, submitLabel: "Purge permanently", danger: true });
    if (!ok) return;
    const result = await post(`/platform/customers/${enc(org)}/purge`, { confirm_organization_id: org, reason });
    closeCustomer();
    setStatus(`${org} purged: ${Object.values(result.deleted || {}).reduce((n, v) => n + asNum(v), 0)} row(s) deleted, ${result.api_keys_revoked} API key(s) revoked.`, "ok");
    await loadPortal();
  }));
  // Suspend, resume and archive from the Customer 360 header: the same endpoints and
  // confirmations as the drawer, with the audit reason collected in the dialog itself.
  async function lifecycleAction(org, action) {
    const copy = {
      suspend: ["Suspend", "Customer requests for this organization are refused until it is resumed. Platform administration is unaffected.", true],
      resume: ["Resume", "Customer requests for this organization are accepted again.", false],
      archive: ["Archive", "The organization is marked archived. Its data is kept; purge separately if the contract requires deletion.", true]
    }[action];
    if (!copy || !org) return false;
    const values = await openDialog({ title: `${copy[0]} ${org}?`, body: copy[1], reason: true, submitLabel: copy[0], danger: copy[2] });
    if (!values) return false;
    await post(`/platform/customers/${enc(org)}/${action}`, { reason: values.reason });
    setStatus(`${org} ${action === "suspend" ? "suspended" : action === "resume" ? "resumed" : "archived"}.`, "ok");
    await loadPortal();
    return true;
  }
  $("gdprBtn")?.addEventListener("click", run(async () => { if (!selectedOrg) return; text("detailStatusText", "Preparing GDPR export..."); await download(`/platform/customers/${enc(selectedOrg)}/export`, `pq-gdpr-export-${selectedOrg}.json`); text("detailStatusText", "GDPR export downloaded."); }));
  $("detailLoginsBtn")?.addEventListener("click", run(async () => {
    if (!selectedOrg) return;
    const query = new URLSearchParams({ limit: "1000" });
    if ($("detailLoginsSince").value) query.set("since", $("detailLoginsSince").value);
    const d = await api(`/platform/customers/${enc(selectedOrg)}/logins?${query}`);
    renderLogs(d.items || [], $("detailLogins"));
  }));
  $("detailFeatureFlags")?.addEventListener("click", run(async event => {
    const button = event.target.closest("[data-flag-delete]");
    if (!button || !selectedOrg) return;
    const org = selectedOrg, version = detailVersion, flag = button.dataset.flagDelete;
    const values = await openDialog({ title: `Remove the ${flag} override`, body: "The feature falls back to the platform default for this customer.", reason: true, submitLabel: "Remove override", danger: true });
    if (!values) return;
    await api(`/platform/customers/${enc(org)}/feature-flags/${enc(flag)}?reason=${enc(values.reason)}`, { method: "DELETE" });
    const flags = await api(`/platform/customers/${enc(org)}/feature-flags`);
    if (version === detailVersion) renderFeatureFlags(flags.items || []);
  }));
  document.querySelectorAll("[data-scroll-to]").forEach(button => button.addEventListener("click", () => { const target = $(button.dataset.scrollTo); if (target) target.scrollIntoView({ block: "start" }); }));
  document.querySelectorAll("[data-jump]").forEach(button => button.addEventListener("click", () => jumpTo(button.dataset.jump)));

  // ── Session ───────────────────────────────────────────────────────────────
  function signOut() {
    sessionVersion++;
    requests.forEach(controller => controller.abort());
    for (const store of [sessionStorage, localStorage]) STORAGE_KEYS.forEach(name => store.removeItem(name));
    if (sessionAuth.active) {
      // End the server-side session too; the cookie alone would otherwise stay valid until it expires.
      fetch("/platform/session/logout", { method: "POST", headers: { "x-csrf-token": sessionAuth.csrf }, credentials: "same-origin", keepalive: true })
        .catch(() => {}).finally(() => location.replace("/vendor-admin/"));
      return;
    }
    location.reload();
  }

  // ── Wiring ────────────────────────────────────────────────────────────────
  const reportLoadError = err => { setApi("API blocked", "bad"); setStatus(err.message || String(err), "bad"); };
  els.load?.addEventListener("click", () => loadPortal().catch(reportLoadError));
  els.reloadAll?.addEventListener("click", () => loadPortal().catch(reportLoadError));
  els.key?.addEventListener("keydown", event => { if (event.key === "Enter") { event.preventDefault(); loadPortal().catch(reportLoadError); } });
  els.quickGate?.addEventListener("click", () => { showView("launch"); loadGate().catch(err => setStatus(err.message, "bad")); });
  els.quickTenant?.addEventListener("click", run(runTenantProbe));
  els.tenantVerifyBtn?.addEventListener("click", run(runTenantProbe));
  els.refreshLogs?.addEventListener("click", () => loadAuthHistory().catch(err => setStatus(err.message, "bad")));
  $("authEventType")?.addEventListener("change", () => loadAuthHistory().catch(err => setStatus(err.message, "bad")));
  $("authUserFilter")?.addEventListener("change", () => loadAuthHistory().catch(err => setStatus(err.message, "bad")));
  $("authSince")?.addEventListener("change", () => loadAuthHistory().catch(err => setStatus(err.message, "bad")));
  els.healthBtn?.addEventListener("click", () => api("/platform/health").then(renderHealth).catch(err => setStatus(err.message, "bad")));
  els.readinessBtn?.addEventListener("click", () => api("/platform/readiness").then(renderReadiness).catch(err => setStatus(err.message, "bad")));
  els.telemetryBtn?.addEventListener("click", run(async () => { const [m, h, r, s] = await Promise.all([api("/platform/metrics"), api("/platform/health"), api("/platform/readiness"), api("/platform/security-truth?limit=80")]); renderTelemetry(m, h, r, s); }));
  els.incidentsBtn?.addEventListener("click", run(loadIncidents));
  $("observabilityBtn")?.addEventListener("click", run(loadObservability));
  els.eventsBtn?.addEventListener("click", event => { if (event.target.form) return; loadEvents(0).catch(err => setStatus(err.message, "bad")); });
  els.securityTruthBtn?.addEventListener("click", () => api("/platform/security-truth?limit=80").then(renderSecurityTruth).catch(err => setStatus(err.message, "bad")));
  els.autopatchBtn?.addEventListener("click", () => loadAutopatches().catch(err => setStatus(err.message, "bad")));
  $("autopatchStatus")?.addEventListener("change", () => loadAutopatches().catch(err => setStatus(err.message, "bad")));
  $("rlsBtn")?.addEventListener("click", run(loadRlsPlan));
  $("retentionPolicyBtn")?.addEventListener("click", run(loadRetentionPolicy));
  $("stateCoverageBtn")?.addEventListener("click", run(loadStateCoverage));
  $("migrateDryRunBtn")?.addEventListener("click", run(() => migrateState(true)));
  $("migrateRunBtn")?.addEventListener("click", run(() => migrateState(false)));
  $("logStorageBtn")?.addEventListener("click", run(loadLogStorage));
  $("createCustomerForm")?.addEventListener("submit", run(async () => {
    const org = $("newOrgId").value.trim(), name = $("newOrgName").value.trim(), reason = $("newOrgReason").value.trim();
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{1,127}$/.test(org)) { note("createCustomerStatus", "Organization id: 2-128 letters, digits, dot, dash, underscore or colon, starting with a letter or digit.", "bad"); $("newOrgId").focus(); return; }
    if (!name || reason.length < 3) { note("createCustomerStatus", "Enter a display name and a reason.", "bad"); return; }
    await post("/platform/customers", { organization_id: org, name, plan_type: $("newOrgPlan").value.trim() || "starter", subscription_status: $("newOrgStatus").value, reason });
    $("createCustomerForm").reset();
    $("newOrgPlan").value = "starter";
    note("createCustomerStatus", `Created ${org}.`, "ok");
    await loadPortal();
  }));
  els.search?.addEventListener("input", () => { orgTable.page = 0; renderCustomers(); });
  els.statusFilter?.addEventListener("change", () => { orgTable.page = 0; renderCustomers(); });
  function rememberCredential() {
    if (sessionAuth.active) return; // SSO: the HttpOnly cookie is the credential; never copy anything into storage
    sessionStorage.setItem("morrow_platform_admin_key", key());
    sessionStorage.setItem("morrow_platform_admin_role", els.role.value);
    renderRemember();
  }
  els.save?.addEventListener("click", run(async () => {
    if (sessionAuth.active) { setStatus("SSO sessions are held in a secure cookie and end after inactivity; nothing is stored in this tab.", "ok"); return; }
    if (remembered()) {
      STORAGE_KEYS.forEach(name => sessionStorage.removeItem(name));
      renderRemember();
      setStatus("This tab no longer remembers the credential. It stays signed in until you reload.", "ok");
      return;
    }
    await api("/platform/whoami", { noRole: true });
    rememberCredential();
    setStatus("Credential remembered for this tab. Sign out to remove it.", "ok");
  }));
  els.clear?.addEventListener("click", signOut);
  els.closeDrawer?.addEventListener("click", closeCustomer);
  els.closeDrawerBackdrop?.addEventListener("click", closeCustomer);
  els.saveCustomer?.addEventListener("click", () => saveSelected().catch(err => text("detailStatusText", err.message || String(err))));
  els.suspend?.addEventListener("click", () => actionSelected("suspend").catch(err => text("detailStatusText", err.message || String(err))));
  els.resume?.addEventListener("click", () => actionSelected("resume").catch(err => text("detailStatusText", err.message || String(err))));
  els.auditPackage?.addEventListener("click", run(async () => { if (!selectedOrg) return; await download(`/platform/customers/${enc(selectedOrg)}/audit-package`, `pq-audit-package-${selectedOrg}.zip`); }));
  els.saveFeatureFlag?.addEventListener("click", run(async () => {
    if (!selectedOrg) return;
    const org = selectedOrg, version = detailVersion;
    const flagKey = $("featureFlagKey").value.trim();
    if (!flagKey) { text("detailStatusText", "Enter a flag key."); $("featureFlagKey").focus(); return; }
    await api(`/platform/customers/${enc(org)}/feature-flags`, { method: "PUT", json: { flag_key: flagKey, enabled: $("featureFlagEnabled").value === "true", reason: $("featureFlagReason").value || "" } });
    const flags = await api(`/platform/customers/${enc(org)}/feature-flags`);
    if (version === detailVersion) renderFeatureFlags(flags.items || []);
  }));
  $("feedbackBtn")?.addEventListener("click", () => loadFeedback().catch(err => setStatus(err.message, "bad")));
  ["feedbackStatus", "feedbackCategory", "feedbackOrg"].forEach(id => $(id)?.addEventListener("change", () => loadFeedback().catch(err => setStatus(err.message, "bad"))));
  $("gateBtn")?.addEventListener("click", () => loadGate().catch(err => setStatus(err.message, "bad")));
  $("trafficBtn")?.addEventListener("click", () => loadTraffic().catch(err => setStatus(err.message, "bad")));

  // Delegated retry for every failure state rendered with failBox/failRow.
  const retryLoaders = {
    portal: () => loadPortal(), users: loadAccess, "api-keys": loadKeys, sessions: loadSessions, audit: () => loadEvents(0),
    "tenant-audit": () => $("tenantAuditFilters")?.requestSubmit(), feedback: loadFeedback, trials: loadTrialRequests, gate: loadGate, traffic: loadTraffic,
    health: () => loadViewData("health"), invitations: loadInvites, operators: loadOperators, data: () => loadViewData("data"),
    maintenance: loadMaintenance, announcements: loadAnnouncements, rls: loadRlsPlan
  };
  document.addEventListener("click", event => {
    const button = event.target.closest("[data-retry]");
    if (!button) return;
    const loader = retryLoaders[button.dataset.retry];
    if (!loader) return; // other modules register their own retry keys
    button.disabled = true;
    Promise.resolve().then(loader).catch(err => setStatus(err.message || String(err), "bad"));
  });

  els.rememberCheck = $("rememberCheck");
  ["morrow_platform_admin_key", "morrow_platform_key", "morrow_platform_admin_role"].forEach(name => localStorage.removeItem(name));
  if (els.key) els.key.value = sessionStorage.getItem("morrow_platform_admin_key") || "";
  if (els.role) els.role.value = sessionStorage.getItem("morrow_platform_admin_role") || "owner";
  if (els.rememberCheck) els.rememberCheck.checked = remembered();
  els.role.addEventListener("change", () => { applyRoleControls(); document.dispatchEvent(new CustomEvent("admin:role")); });
  applyRoleControls();


  /* Trial requests: the queue behind /trial. The decision is the whole point -- an approval
     creates an organization and issues a single-use invitation, and the invitation token is
     returned exactly once, so it is shown in a dialog to copy rather than stored anywhere. */
  async function loadTrialRequests() {
    const status = $("trialStatus")?.value ?? "pending";
    const body = $("trialBody");
    try {
      const d = await api("/platform/trial-requests" + (status ? `?status=${enc(status)}` : ""));
      const counts = d.counts || {};
      const pill = $("trialCount");
      if (pill) {
        const pending = asNum(counts.pending);
        pill.textContent = `${fmt.format(pending)} pending`;
        pill.className = `pill ${pending ? "warn" : "ok"}`;
      }
      const items = d.requests || [];
      const head = `<div class="riskItem"><b>${fmt.format(asNum(counts.total))} total</b><span>${["pending", "approved", "declined", "spam"].map(k => `${k} ${fmt.format(asNum(counts[k]))}`).join(" - ")}</span></div>`;
      if (body) body.innerHTML = head + (items.map(trialRow).join("") || empty("No trial requests match this filter."));
      applyRoleControls();
      return d;
    } catch (err) {
      if (body) body.innerHTML = failBox(`Trial requests unavailable: ${err.message || err}`, "trials");
      throw err;
    }
  }

  function trialRow(r) {
    const useCase = String(r.use_case || "");
    const shown = useCase.length > 240
      ? `<details class="detailsBlock"><summary>${esc(useCase.slice(0, 240))}&hellip;</summary><p>${esc(useCase)}</p></details>`
      : (useCase ? `<span>${esc(useCase)}</span>` : "");
    const who = [r.name, r.company].filter(Boolean).map(esc).join(" - ") || "no name given";
    /* The domain is the strongest signal on a request, so it links straight to that domain's
       public record: one click shows whether they plainly operate it and what it negotiates. */
    const domain = r.domain
      ? `<a class="mono" href="/r/${encodeURIComponent(r.domain)}" target="_blank" rel="noopener">${esc(r.domain)}</a>`
      : `<span class="mono">no domain given</span>`;
    const decided = r.decided_at
      ? `<span class="mono">${esc(r.status)} by ${esc(r.decided_by || "operator")} - ${esc(fmtTime(r.decided_at, ""))}${r.organization_id ? ` - ${esc(r.organization_id)}` : ""}</span>`
      : "";
    const actions = r.status === "pending"
      ? `<div class="row"><button class="btn primary small" data-write data-trial="approve" data-id="${esc(r.id)}" data-company="${esc(r.company || "")}" data-email="${esc(r.email || "")}" type="button">Approve</button><button class="btn secondary small" data-write data-trial="decline" data-id="${esc(r.id)}" type="button">Decline</button><button class="btn danger small" data-write data-trial="spam" data-id="${esc(r.id)}" type="button">Spam</button></div>`
      : "";
    return `<div class="event" data-record-id="${esc(r.id)}"><b>${esc(r.email)} ${statusPill(r.status === "pending" ? "new" : r.status)}</b><span>${who}</span>${domain}${shown}<span class="mono">asked ${esc(fmtTime(r.created_at, ""))}</span>${decided}${r.note ? `<span class="mono warnText">note: ${esc(r.note)}</span>` : ""}${actions}</div>`;
  }

  $("trialBody")?.addEventListener("click", run(async event => {
    const button = event.target.closest("[data-trial]");
    if (!button) return;
    const action = button.dataset.trial;
    const id = button.dataset.id;

    if (action !== "approve") {
      const values = await openDialog({
        title: action === "spam" ? "Mark this request as spam" : "Decline this request",
        body: "The note is visible to platform operators only. The row is kept either way, so a second request from the same address can be read in context.",
        fields: [{ name: "note", label: "Note" }],
        submitLabel: action === "spam" ? "Mark spam" : "Decline",
        danger: true
      });
      if (!values) return;
      await api(`/platform/trial-requests/${enc(id)}/decline`, { method: "POST", json: { note: values.note, spam: action === "spam" } });
      setStatus(`Request ${id} ${action === "spam" ? "marked spam" : "declined"}.`, "ok");
      await loadTrialRequests();
      return;
    }

    const values = await openDialog({
      title: `Approve ${button.dataset.email}`,
      body: "This creates the organization and issues a single-use invitation to that address. The invitation link is shown once and stored nowhere, so copy it before closing.",
      fields: [
        { name: "organization_name", label: "Organization name", value: button.dataset.company || "" },
        { name: "plan_type", label: "Plan", value: "trial" },
        { name: "expires_hours", label: "Invitation valid for (hours)", value: "168" },
        { name: "note", label: "Note (operators only)" }
      ],
      submitLabel: "Create organization and invite"
    });
    if (!values) return;
    const result = await api(`/platform/trial-requests/${enc(id)}/approve`, {
      method: "POST",
      json: {
        organization_name: values.organization_name,
        plan_type: values.plan_type || "trial",
        expires_hours: Number(values.expires_hours) || 168,
        note: values.note
      }
    });
    const approved = result.request || {};
    /* The fragment, not a query string: static/invite.js reads #token= and immediately strips it,
       because a token in a query string reaches access logs and Referer headers. */
    const link = `${location.origin}/invite#token=${encodeURIComponent(approved.invite_token || "")}`;

    /* Send it, if this server can send mail. The route looks the pending token up itself, so the
       token never travels through this request. If mail is not configured the operator copies the
       link below, which is the documented fallback rather than a failure. */
    let delivery = "";
    if (approved.organization_id && approved.invite_id) {
      try {
        const status = await api("/platform/invitations/email-status");
        if (status.email_configured) {
          await api(`/platform/customers/${enc(approved.organization_id)}/invitations/${enc(approved.invite_id)}/email`, { method: "POST", json: { reason: "trial request approved" } });
          delivery = `Emailed to ${esc(approved.invite_email || "")}.`;
        } else {
          delivery = "Email is not configured on this server, so send the link below yourself.";
        }
      } catch (err) {
        /* The organization and the invitation both exist either way, so this reports rather than
           throws: losing the link here would mean revoking and reissuing for no reason. */
        delivery = `The invitation was created but not emailed (${esc(err.message || err)}). Send the link below.`;
      }
    }

    await openDialog({
      title: "Invitation created",
      /* Shown once. There is no second chance to read it: the token is not in the request row and
         not in the audit log, so a lost link is revoked and reissued rather than recovered. */
      body: `Organization ${esc(approved.organization_id || "")} created for ${esc(approved.invite_email || "")} as ${esc(approved.role || "org_admin")}. It works once and expires ${esc(fmtTime(approved.invite_expires_at, "soon"))}. ${delivery} ${trialCapNote(approved.caps)}`,
      fields: [{ name: "link", label: "Invitation link (copy it now)", value: link }],
      submitLabel: "Done"
    });
    setStatus(`Organization created for ${approved.invite_email || id}.`, "ok");
    await loadTrialRequests();
  }));

  /* Say what the new organization may do, so the caps are visible at the moment they are set
     rather than discovered later under Access -> Rate limits. */
  function trialCapNote(caps) {
    if (!caps) return "";
    if (caps.error) return `Caps: ${esc(caps.error)}.`;
    const api = asNum(caps.api_calls_per_min);
    const scans = asNum(caps.scans_per_hour);
    if (!api && !scans) return "No per-organization caps were applied (MORROW_TRIAL_* are unset), so it runs on the platform defaults.";
    return `Capped at ${api ? `${fmt.format(api)} API calls/min` : "the platform default for API calls"} and ${scans ? `${fmt.format(scans)} scans/hour` : "the platform default for scans"}.`;
  }

  $("trialBtn")?.addEventListener("click", run(() => loadTrialRequests()));
  $("trialStatus")?.addEventListener("change", run(() => loadTrialRequests()));

  window.AirlockAdmin = {
    $, esc, fmt, asNum, text, empty, emptyRow, skeletonRows, skeletonList, failBox, failRow, fmtTime, statusKind, statusPill, riskPill, tags, kv, run,
    api, safeApi, post, download, openDialog, setStatus, setApi, note,
    key, role, canWrite, isOwner, isConnected: () => connected, identity: () => identity, customers: () => customers, metrics: () => lastMetrics,
    incidentsSummary: () => lastIncidents, remembered, loadPortal, loadGate, loadTraffic, runTenantProbe, loadViewData, loadFeedback, loadFeedbackItem, loadTrialRequests, loadAutopatches, showAutopatch,
    applyRoleControls, populateOrgSelects, selectOrg, reportLoadError,
    openCustomer, closeCustomer, drawerOpen: () => els.drawer.classList.contains("open"), dialogOpen: () => !els.dialog.hidden,
    signOut, lifecycle: lifecycleAction,
    useSession: csrf => { sessionAuth.active = true; sessionAuth.csrf = String(csrf || ""); STORAGE_KEYS.forEach(name => sessionStorage.removeItem(name)); if (els.key) els.key.value = ""; },
    sessionMode: () => sessionAuth.active
  };
  // A credential remembered for this tab reconnects without asking again.
  if (remembered() && key()) loadPortal().catch(reportLoadError);
})();
