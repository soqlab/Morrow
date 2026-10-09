(() => {
  "use strict";
  /* ==========================================================================
     Vendor support "view as customer" (read-only).

     - Customer 360 header: "View as customer (read-only)" opens a dialog for the
       reason, duration and ticket, warns that access is logged and visible to
       the customer, then opens the one-time launch URL in a new tab.
     - Customer 360 card: this organization's active support sessions, with revoke.
     - Customers > Support sessions (#/support-sessions): every session, filtered.

     The launch URL carries a single-use code valid for 60 seconds, never a token.
     The new tab is opened with noopener so it does not inherit this tab's
     sessionStorage (which holds the platform key).
     ========================================================================== */

  const A = window.AirlockAdmin;
  if (!A) return;
  const { $, esc, fmtTime, statusPill, emptyRow, failRow, skeletonRows } = A;
  const enc = encodeURIComponent;
  const CREATE_ROLES = ["owner", "operator", "support"];
  const DURATIONS = [5, 15, 30, 45, 60];
  const canStart = () => A.isConnected() && CREATE_ROLES.includes(A.role());
  const app = () => window.AdminApp;
  const orgNow = () => (app()?.current?.() || {}).org || "";

  function remaining(expiresAt) {
    const ms = Date.parse(expiresAt) - Date.now();
    if (!Number.isFinite(ms) || ms <= 0) return "ended";
    const m = Math.floor(ms / 60000), s = Math.floor((ms % 60000) / 1000);
    return `${m}m ${String(s).padStart(2, "0")}s left`;
  }
  function sessionRow(s, { showOrg = true } = {}) {
    const active = s.status === "active";
    const ticket = s.ticket_ref ? ` · ticket ${esc(s.ticket_ref)}` : "";
    const glass = s.break_glass ? ` <span class="pill bad">break-glass</span>` : "";
    return `<tr data-support-row="${esc(s.id)}" data-record-id="${esc(s.id)}" data-record-org="${esc(s.organization_id)}" data-record-active="${active ? "1" : ""}">
      <td><div class="cellStack"><b class="mono">${esc(s.id)}</b><span class="muted">${esc(s.minutes)} min${ticket}</span></div></td>
      ${showOrg ? `<td><a href="#/customers/${esc(enc(s.organization_id))}" class="mono">${esc(s.organization_id)}</a></td>` : ""}
      <td><div class="cellStack"><b>${esc(s.operator_display || s.operator_id)}</b><span class="muted">${esc(s.operator_role || "")}</span></div></td>
      <td><div class="cellStack"><span>${esc(s.reason)}</span>${glass}</div></td>
      <td class="mono">${esc(fmtTime(s.created_at))}</td>
      <td class="mono">${active ? esc(remaining(s.expires_at)) : esc(fmtTime(s.revoked_at || s.expires_at))}</td>
      <td class="num">${esc(s.request_count || 0)}</td>
      <td>${statusPill(s.status)}${s.revoked_by ? `<div class="muted">${esc(s.revoked_by)}</div>` : ""}</td>
      <td>${active ? `<button class="btn danger small" type="button" data-support-revoke="${esc(s.id)}"${canStart() ? "" : " disabled"}>Revoke&hellip;</button>` : ""}
        <details class="detailsBlock" data-support-journal="${esc(s.id)}"><summary>Request journal</summary><div class="muted">Open to load.</div></details></td>
    </tr>`;
  }

  // ---------- start a session ----------
  async function startSession(org, name, status) {
    if (!org) return;
    if (!canStart()) { A.setStatus("Starting a support session requires the owner, operator or support role.", "bad"); return; }
    const values = await A.openDialog({
      title: `View ${name || org} as the customer (read-only)`,
      body: "Opens this customer's console in a new tab, read-only and time-limited. Every page you open is logged against the session, and the customer sees \"Vendor support viewed your workspace\" with your name, reason and duration in their audit log. Vault, secrets, exports and vendor controls stay blocked. The launch link works once, within 60 seconds."
        + (status === "suspended" || status === "archived" ? ` This organization is ${status}: only an owner can open a session, and customer pages may still refuse requests.` : ""),
      fields: [
        { name: "minutes", label: "Duration", type: "select", value: "30", options: DURATIONS.map(m => ({ value: String(m), label: `${m} minutes` })) },
        { name: "ticket_ref", label: "Ticket reference (optional)", value: "" }
      ],
      reason: true,
      submitLabel: "Start read-only session",
      validate: v => (String(v.reason || "").trim().length < 10 ? "Enter a reason of at least 10 characters. The customer will see it." : String(v.ticket_ref || "").length > 80 ? "Ticket reference is limited to 80 characters." : "")
    });
    if (!values) return;
    const body = { reason: values.reason.trim(), minutes: Number(values.minutes) || 30, ticket_ref: String(values.ticket_ref || "").trim() };
    let res = await A.safeApi(`/platform/customers/${enc(org)}/support-sessions`, { method: "POST", json: body });
    if (!res.ok && res.status === 403 && /disabled support access/i.test(res.error || "")) {
      A.setStatus(`${name || org} has not permitted vendor support access. Ask the customer's organization admin to approve it in Data Control. Platform owners cannot override this decision.`, "bad");
      return;
    }
    if (!res.ok) { A.setStatus(`Support session not started: ${res.error}`, "bad"); return; }
    const url = new URL(res.data.launch_url, location.origin).href;
    window.open(url, "_blank", "noopener,noreferrer");
    const host = $("c360SupportLaunch");
    if (host) {
      host.hidden = false;
      host.innerHTML = `<div class="notice info"><b>Support session started until ${esc(fmtTime(res.data.session.expires_at))}.</b> The customer console opened in a new tab. If your browser blocked it, <a href="${esc(url)}" target="_blank" rel="noopener noreferrer">open the console</a> within 60 seconds; the link works once.</div>`;
      setTimeout(() => { host.hidden = true; host.innerHTML = ""; }, 60000);
    }
    A.setStatus(`Read-only support session ${res.data.session.id} started for ${org}.`, "ok");
    await Promise.allSettled([render360(org), orgNow() ? null : loadPage()]);
  }

  async function revoke(id) {
    const values = await A.openDialog({ title: `Revoke support session ${id}`, body: "The session's token stops working within seconds and the customer's audit log records the revoke.", reason: true, submitLabel: "Revoke session", danger: true });
    if (!values) return;
    await A.api(`/platform/support-sessions/${enc(id)}/revoke`, { method: "POST", json: { reason: values.reason } });
    A.setStatus(`Support session ${id} revoked.`, "ok");
    const org = orgNow();
    if (org) await render360(org);
    if ((app()?.current?.() || {}).key === "support-sessions") await loadPage();
  }

  async function loadJournal(details) {
    if (details.dataset.loaded) return;
    details.dataset.loaded = "1";
    const box = details.querySelector("div");
    const res = await A.safeApi(`/platform/support-sessions/${enc(details.dataset.supportJournal)}?limit=100`);
    if (!res.ok) { box.textContent = `Journal unavailable: ${res.error}`; return; }
    const items = res.data.requests || [];
    box.innerHTML = items.length ? `<pre class="codeBlock">${esc(items.map(r => `${fmtTime(r.created_at)}  ${r.status_code}  ${r.method} ${r.path}`).join("\n"))}</pre>` : `<span class="muted">No requests yet.</span>`;
  }

  // ---------- Customer 360 ----------
  let seq = 0;
  async function render360(org) {
    const body = $("c360SupportSessions");
    const btn = $("c360SupportBtn");
    if (btn) { btn.disabled = !canStart(); btn.title = canStart() ? "" : "Requires the owner, operator or support role."; }
    if (!body || !org) return;
    const mine = ++seq;
    body.innerHTML = skeletonRows(9, 2);
    const res = await A.safeApi(`/platform/support-sessions?organization_id=${enc(org)}&active=true&limit=50`);
    if (mine !== seq) return;
    if (!res.ok) { body.innerHTML = res.status === 404 ? emptyRow(8, "Support sessions are not available on this server yet.") : failRow(8, `Support sessions unavailable: ${res.error}`, "c360"); return; }
    const items = res.data.items || [];
    body.innerHTML = items.length ? items.map(s => sessionRow(s, { showOrg: false })).join("") : emptyRow(8, "No active support sessions for this organization.");
  }

  // ---------- Customers > Support sessions ----------
  async function loadPage() {
    const body = $("supportSessionsBody");
    if (!body) return;
    const q = (app()?.current?.() || {}).query;
    const deepOrg = q?.get?.("org");
    if (deepOrg && $("supportFilterOrg")) {
      const sel = $("supportFilterOrg");
      if (![...sel.options].some(o => o.value === deepOrg)) sel.add(new Option(deepOrg, deepOrg));
      sel.value = deepOrg;
    }
    const org = $("supportFilterOrg")?.value || "";
    const state = $("supportFilterStatus")?.value || "";
    const who = ($("supportFilterOperator")?.value || "").trim().toLowerCase();
    body.innerHTML = skeletonRows(9, 4);
    const params = new URLSearchParams({ limit: "500" });
    if (org) params.set("organization_id", org);
    if (state) params.set("active", state === "active" ? "true" : "false");
    const res = await A.safeApi(`/platform/support-sessions?${params}`);
    if (!res.ok) { body.innerHTML = res.status === 404 ? emptyRow(9, "Support sessions are not available on this server yet.") : failRow(9, `Support sessions unavailable: ${res.error}`); return; }
    const items = (res.data.items || []).filter(s => !who || `${s.operator_display} ${s.operator_id} ${s.ticket_ref}`.toLowerCase().includes(who));
    body.innerHTML = items.length ? items.map(s => sessionRow(s)).join("") : emptyRow(9, "No support sessions match these filters.");
    const active = items.filter(s => s.status === "active").length;
    const note = $("supportSessionsNote");
    if (note) note.textContent = `${items.length} session(s), ${active} active. Sessions are read-only, last 5 to 60 minutes, and appear in the customer's audit log.`;
  }

  // ---------- wiring ----------
  document.addEventListener("click", A.run(async event => {
    const start = event.target.closest("#c360SupportBtn");
    if (start) {
      const org = orgNow();
      const known = A.customers().find(c => c.organization_id === org) || {};
      await startSession(org, $("c360Name")?.textContent || known.name || org, String(known.subscription_status || "").toLowerCase());
      return;
    }
    const rev = event.target.closest("[data-support-revoke]");
    if (rev) await revoke(rev.dataset.supportRevoke);
  }));
  document.addEventListener("toggle", event => {
    const details = event.target;
    if (details?.dataset?.supportJournal && details.open) loadJournal(details).catch(() => {});
  }, true);
  $("supportFilters")?.addEventListener("submit", A.run(async event => { event.preventDefault(); await loadPage(); }));
  $("supportFilterOrg")?.addEventListener("change", () => loadPage().catch(() => {}));
  $("supportFilterStatus")?.addEventListener("change", () => loadPage().catch(() => {}));
  document.addEventListener("admin:role", () => { const org = orgNow(); if (org) render360(org).catch(() => {}); });

  window.AdminSupport = { render360, loadPage, startSession };
})();
