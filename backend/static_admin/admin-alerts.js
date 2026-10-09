(() => {
  "use strict";
  /* ==========================================================================
     Operations › Alert routing (#/alert-routing).

     Channels (GET/POST /platform/alert-channels, PUT/DELETE /platform/alert-channels/{id}),
     test sends (POST /platform/alert-channels/{id}/test) and the delivery log
     (GET /platform/alert-deliveries). Registered as window.AdminAlerts; admin-views.js
     calls load() when the route opens. Secrets are write-only: the server returns a
     masked target_hint, and editing with an empty target keeps the stored secret.
     ========================================================================== */

  const A = window.AirlockAdmin;
  if (!A) return;
  const { $, esc, fmt, emptyRow, skeletonRows, fmtTime, statusPill, text } = A;
  const enc = encodeURIComponent;
  const NOT_AVAILABLE = "Not available on this server yet.";
  const KIND_LABELS = { slack_webhook: "Slack", email: "Email", pagerduty: "PagerDuty", generic_webhook: "Webhook" };
  const TARGET_COPY = {
    slack_webhook: ["Slack incoming webhook URL", "https://hooks.slack.com/services/… (create one under Slack app › Incoming Webhooks)."],
    email: ["Recipient addresses", "Comma-separated, up to 20."],
    pagerduty: ["PagerDuty integration key", "Events API v2 integration (routing) key from the service's Integrations tab."],
    generic_webhook: ["Webhook URL", "https only. Receives a JSON POST; private and internal addresses are refused."]
  };
  const SEVERITY_LABELS = { critical: "Critical only", warn: "Warn +", info: "Everything" };
  const state = { data: null, editing: null, back: null, channels: [] };

  const errorRow = (cols, message, retry) => `<tr><td colspan="${cols}"><div class="errorState" role="alert"><span>${esc(message)}</span><button class="btn secondary small" type="button" data-alert-retry="${esc(retry)}">Retry</button></div></td></tr>`;
  const unavailableRow = (cols, what) => `<tr><td colspan="${cols}"><div class="emptyState unavailableState"><b>${esc(NOT_AVAILABLE)}</b><span>${esc(what)}</span></div></td></tr>`;
  const quietText = q => (q ? `${q.start}–${q.end} ${q.timezone}${q.allow_critical ? " (critical still sent)" : ""}` : "None");

  // ---------- channels ----------
  async function loadChannels() {
    const body = $("alertChannelsBody");
    if (!body.querySelector("tr:not(.skeletonRow)")) body.innerHTML = skeletonRows(7, 3);
    const res = await A.safeApi("/platform/alert-channels");
    text("alertsRefreshed", `Refreshed ${new Date().toLocaleTimeString()}`);
    if (!res.ok) {
      state.data = null;
      $("alertsSettings").innerHTML = "";
      body.innerHTML = res.status === 404 ? unavailableRow(7, "Alert routing needs GET /platform/alert-channels.") : errorRow(7, `Alert channels could not be loaded: ${res.error}`, "channels");
      return;
    }
    const d = state.data = res.data;
    state.channels = d.items || [];
    const s = d.settings || {}, job = d.dispatcher || {};
    const warnings = [];
    if (!d.secret_storage_configured) warnings.push(`<div class="notice warn"><b>Secret storage is not configured.</b> Set PQC_VAULT_MASTER_KEY to add Slack, PagerDuty or webhook channels; their targets are stored encrypted.</div>`);
    if (!d.email_configured) warnings.push(`<div class="notice warn"><b>Email isn't configured.</b> Email channels can be saved, but sends fail until PQC_SMTP_HOST and PQC_SMTP_FROM are set.</div>`);
    if (s.dispatch_enabled === false) warnings.push(`<div class="notice bad"><b>The dispatcher is off.</b> PQC_ALERT_DISPATCH_ENABLED=0, so nothing is sent automatically. Test sends still work.</div>`);
    if (job.last_error) warnings.push(`<div class="notice bad"><b>Last dispatch run reported a problem.</b> ${esc(job.last_error)}</div>`);
    $("alertsSettings").innerHTML = warnings.join("") + `<p class="copy">Dispatcher ${statusPill(job.status || "unknown")} · last run ${esc(fmtTime(job.last_run_at, "never"))} · every ${esc(fmt.format(Number(s.interval_seconds || 60)))}s · renotify after ${esc(fmt.format(Number(s.renotify_hours || 24)))}h · at most ${esc(fmt.format(Number(s.rate_cap || 20)))} messages per ${esc(fmt.format(Number(s.rate_window_minutes || 10)))} min per channel, then one digest.</p>`;
    body.innerHTML = state.channels.length ? state.channels.map(c => `<tr data-record-id="${esc(c.id)}">
      <td><div class="cellStack"><b>${esc(c.name)}</b><span class="mono muted">${esc(KIND_LABELS[c.kind] || c.kind)} · ${esc(c.id)}</span></div></td>
      <td><div class="cellStack"><span class="mono">${esc(c.target_hint || "—")}</span>${c.kind !== "email" ? `<span class="muted">${c.target_encrypted ? "Encrypted at rest" : "Not encrypted"}</span>` : ""}</div></td>
      <td><label class="check"><input type="checkbox" data-alert-toggle="${esc(c.id)}" data-write ${c.enabled ? "checked" : ""} aria-label="Enabled: ${esc(c.name)}"><span>${c.enabled ? "On" : "Off"}</span></label></td>
      <td>${esc(SEVERITY_LABELS[c.min_severity] || c.min_severity)}</td>
      <td>${(c.kinds || []).length ? c.kinds.map(k => `<span class="tag">${esc(((d.notification_kind_labels || {})[k]) || k)}</span>`).join("") : `<span class="muted">All kinds</span>`}</td>
      <td>${esc(quietText(c.quiet_hours))}</td>
      <td><div class="row"><button class="btn secondary small" type="button" data-write data-alert-test="${esc(c.id)}">Send test</button><button class="btn secondary small" type="button" data-write data-alert-edit="${esc(c.id)}">Edit</button><button class="btn danger small" type="button" data-write data-alert-delete="${esc(c.id)}">Delete</button></div></td>
    </tr>`).join("") : `<tr><td colspan="7"><div class="emptyState"><b>No alert channels yet</b><span>Notifications only appear in this portal until you add a channel. Add Slack, email, PagerDuty or a webhook to reach whoever is on call.</span></div></td></tr>`;
    const select = $("alertLogChannel"), chosen = select.value;
    select.innerHTML = `<option value="">All channels</option>` + state.channels.map(c => `<option value="${esc(c.id)}">${esc(c.name)}</option>`).join("");
    if (state.channels.some(c => c.id === chosen)) select.value = chosen;
    A.applyRoleControls();
  }

  // ---------- delivery log ----------
  async function loadDeliveries() {
    const body = $("alertDeliveriesBody");
    if (!body.querySelector("tr:not(.skeletonRow)")) body.innerHTML = skeletonRows(8, 3);
    const params = new URLSearchParams({ limit: "200" });
    [["channel_id", "alertLogChannel"], ["status", "alertLogStatus"], ["event", "alertLogEvent"]].forEach(([key, id]) => { if ($(id).value) params.set(key, $(id).value); });
    const res = await A.safeApi(`/platform/alert-deliveries?${params}`);
    if (!res.ok) {
      body.innerHTML = res.status === 404 ? unavailableRow(8, "The delivery log needs GET /platform/alert-deliveries.") : errorRow(8, `The delivery log could not be loaded: ${res.error}`, "deliveries");
      return;
    }
    const items = res.data.items || [];
    const filtered = params.has("channel_id") || params.has("status") || params.has("event");
    body.innerHTML = items.length ? items.map(i => `<tr>
      <td class="mono">${esc(fmtTime(i.created_at))}</td>
      <td><div class="cellStack"><b>${esc(i.channel_name || i.channel_id)}</b><span class="mono muted">${esc(KIND_LABELS[i.channel_kind] || i.channel_kind)}</span></div></td>
      <td>${esc(i.event)}</td>
      <td>${statusPill(i.status === "sent" ? "ok" : i.status === "failed" ? "failed" : i.status)}</td>
      <td><div class="cellStack"><span>${esc(i.title || "—")}</span>${i.notification_id ? `<span class="mono muted">${esc(i.notification_id)}</span>` : ""}</div></td>
      <td class="num">${i.http_status ?? "—"}</td>
      <td class="num">${i.latency_ms === null || i.latency_ms === undefined ? "—" : `${esc(fmt.format(Number(i.latency_ms)))} ms`}</td>
      <td>${i.error ? esc(i.error) : `<span class="muted">None</span>`}</td>
    </tr>`).join("") : emptyRow(8, filtered ? "No deliveries match these filters." : "No delivery attempts yet. Add a channel and send a test.");
  }

  async function load() {
    await Promise.all([loadChannels(), loadDeliveries()]);
  }

  // ---------- add / edit dialog ----------
  const dialog = () => $("alertDialog");
  function syncTargetCopy() {
    const kind = $("alertKind").value;
    const [label, help] = TARGET_COPY[kind] || ["Target", ""];
    text("alertTargetLabel", label);
    text("alertTargetHelp", state.editing ? `${help} Leave empty to keep the stored ${kind === "email" ? "recipients" : "value"} (${state.editing.target_hint || "hidden"}).` : help);
    $("alertTarget").type = kind === "pagerduty" ? "password" : "text";
    $("alertTarget").placeholder = kind === "email" ? "oncall@example.com, security@example.com" : kind === "pagerduty" ? "32-character integration key" : "https://";
  }
  function openEditor(channel) {
    state.editing = channel || null;
    state.back = document.activeElement;
    // The kind list and labels come from the server (services/platform_analytics NOTIFICATION_KIND_CATALOG).
    const kinds = (state.data && state.data.notification_kinds) || [];
    const labels = (state.data && state.data.notification_kind_labels) || {};
    text("alertDialogTitle", channel ? `Edit ${channel.name}` : "Add alert channel");
    $("alertKind").value = channel ? channel.kind : "slack_webhook";
    $("alertKind").disabled = !!channel;
    $("alertName").value = channel ? channel.name : "";
    $("alertTarget").value = "";
    $("alertSeverity").value = channel ? channel.min_severity : "warn";
    $("alertEnabled").checked = channel ? channel.enabled : true;
    $("alertKinds").innerHTML = kinds.map(k => `<label class="check"><input type="checkbox" value="${esc(k)}" ${channel && (channel.kinds || []).includes(k) ? "checked" : ""}><span>${esc(labels[k] || k.replace(/_/g, " "))}</span></label>`).join("");
    const q = channel && channel.quiet_hours;
    $("alertQuietOn").checked = !!q;
    $("alertQuietFields").hidden = !q;
    $("alertQuietStart").value = q ? q.start : "22:00";
    $("alertQuietEnd").value = q ? q.end : "07:00";
    $("alertQuietTz").value = q ? q.timezone : (Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC");
    $("alertQuietCritical").checked = q ? !!q.allow_critical : true;
    $("alertReason").value = "";
    text("alertDialogError", "");
    syncTargetCopy();
    dialog().hidden = false;
    const shell = $("appShell");
    if (shell) shell.inert = true;
    (channel ? $("alertName") : $("alertKind")).focus();
  }
  function closeEditor() {
    dialog().hidden = true;
    const shell = $("appShell");
    if (shell) shell.inert = false;
    state.editing = null;
    if (state.back && state.back.isConnected) state.back.focus();
  }
  async function submitEditor(event) {
    event.preventDefault();
    const submit = $("alertDialogSubmit");
    const editing = state.editing;
    const kind = $("alertKind").value;
    const name = $("alertName").value.trim();
    const rawTarget = $("alertTarget").value.trim();
    const reason = $("alertReason").value.trim();
    if (!name) { text("alertDialogError", "Enter a channel name."); $("alertName").focus(); return; }
    if (!editing && !rawTarget) { text("alertDialogError", `Enter the ${TARGET_COPY[kind][0].toLowerCase()}.`); $("alertTarget").focus(); return; }
    if (rawTarget && kind !== "email" && kind !== "pagerduty" && !/^https:\/\//i.test(rawTarget)) { text("alertDialogError", "Webhook URLs must start with https://."); $("alertTarget").focus(); return; }
    if (reason.length < 3) { text("alertDialogError", "Enter a reason of at least 3 characters. It is recorded in the audit trail."); $("alertReason").focus(); return; }
    const payload = { name, enabled: $("alertEnabled").checked, min_severity: $("alertSeverity").value, reason,
      kinds: [...$("alertKinds").querySelectorAll("input:checked")].map(i => i.value) };
    if (rawTarget) payload.target = kind === "email" ? rawTarget.split(/[,;\s]+/).filter(Boolean) : rawTarget;
    if ($("alertQuietOn").checked) payload.quiet_hours = { start: $("alertQuietStart").value, end: $("alertQuietEnd").value, timezone: $("alertQuietTz").value.trim() || "UTC", allow_critical: $("alertQuietCritical").checked };
    else if (editing) payload.clear_quiet_hours = true;
    submit.disabled = true;
    try {
      if (editing) await A.api(`/platform/alert-channels/${enc(editing.id)}`, { method: "PUT", json: payload });
      else await A.api("/platform/alert-channels", { method: "POST", json: { kind, ...payload } });
      closeEditor();
      A.setStatus(editing ? `Channel ${name} updated.` : `Channel ${name} added. Send a test to confirm it works.`, "ok");
      await load();
    } catch (err) {
      text("alertDialogError", err.message || String(err));
    } finally { submit.disabled = false; }
  }

  // ---------- row actions ----------
  const byId = id => state.channels.find(c => c.id === id);
  async function testSend(button) {
    const channel = byId(button.dataset.alertTest);
    if (!channel) return;
    const box = $("alertTestResult");
    button.disabled = true;
    box.innerHTML = `<div class="notice"><b>Sending a test to ${esc(channel.name)}…</b></div>`;
    try {
      const r = await A.api(`/platform/alert-channels/${enc(channel.id)}/test`, { method: "POST", json: { reason: "test send from the admin portal" }, timeout: 45000 });
      box.innerHTML = r.ok
        ? `<div class="notice ok"><b>Test delivered to ${esc(channel.name)}.</b> ${r.http_status ? `HTTP ${esc(r.http_status)}, ` : ""}${esc(fmt.format(Number(r.latency_ms || 0)))} ms. Check the destination for a message labelled [TEST].</div>`
        : `<div class="notice bad"><b>Test to ${esc(channel.name)} failed.</b> ${esc(r.error || "No detail was returned.")}${r.http_status ? ` (HTTP ${esc(r.http_status)})` : ""}</div>`;
    } catch (err) {
      box.innerHTML = `<div class="notice bad"><b>Test to ${esc(channel.name)} could not be sent.</b> ${esc(err.message || String(err))}</div>`;
    } finally {
      button.disabled = !A.canWrite();
      loadDeliveries().catch(() => {});
    }
  }
  async function toggle(input) {
    const channel = byId(input.dataset.alertToggle);
    if (!channel) return;
    const enabled = input.checked;
    input.checked = !enabled;   // reflect the stored state until the change is confirmed
    const values = await A.openDialog({ title: `${enabled ? "Enable" : "Disable"} ${channel.name}`, body: enabled ? "Matching notifications start going to this channel on the next dispatcher run." : "Nothing is sent to this channel until it is enabled again. Open PagerDuty incidents raised by this channel are resolved first.", reason: true, submitLabel: enabled ? "Enable channel" : "Disable channel", danger: !enabled });
    if (!values) return;
    try {
      const r = await A.api(`/platform/alert-channels/${enc(channel.id)}`, { method: "PUT", json: { enabled, reason: values.reason } });
      A.setStatus(`${channel.name} ${enabled ? "enabled" : "disabled"}.${r.note ? ` ${r.note}` : ""}`, noteTone(r));
    } catch (err) { A.setStatus(err.message || String(err), "bad"); }
    await loadChannels();
  }
  // "warn" only when something was left for the operator: a resolve that failed or a digest incident.
  const noteTone = r => ((r && r.incidents && (r.incidents.failed || r.incidents.in_digest)) ? "warn" : "ok");

  async function remove(button) {
    const channel = byId(button.dataset.alertDelete);
    if (!channel) return;
    const values = await A.openDialog({ title: `Delete ${channel.name}`, body: "The channel, its stored secret and its dedupe ledger are removed. The delivery log keeps its past attempts.", reason: true, confirmText: channel.name, submitLabel: "Delete channel", danger: true });
    if (!values) return;
    try {
      const r = await A.api(`/platform/alert-channels/${enc(channel.id)}?reason=${enc(values.reason)}`, { method: "DELETE" });
      A.setStatus(`${channel.name} deleted.${r.note ? ` ${r.note}` : ""}`, noteTone(r));
    } catch (err) { A.setStatus(err.message || String(err), "bad"); }
    await load();
  }

  // ---------- wiring ----------
  $("alertsRefreshBtn")?.addEventListener("click", A.run(load));
  $("alertLogRefreshBtn")?.addEventListener("click", A.run(loadDeliveries));
  ["alertLogChannel", "alertLogStatus", "alertLogEvent"].forEach(id => $(id)?.addEventListener("change", A.run(loadDeliveries)));
  $("alertAddBtn")?.addEventListener("click", () => openEditor(null));
  $("alertKind")?.addEventListener("change", syncTargetCopy);
  $("alertQuietOn")?.addEventListener("change", () => { $("alertQuietFields").hidden = !$("alertQuietOn").checked; });
  $("alertDialogForm")?.addEventListener("submit", submitEditor);
  $("alertDialogCancel")?.addEventListener("click", closeEditor);
  $("alertDialogBackdrop")?.addEventListener("click", closeEditor);
  $("alertDialog")?.addEventListener("keydown", event => {
    if (event.key === "Escape") { event.preventDefault(); event.stopPropagation(); closeEditor(); return; }
    if (event.key !== "Tab") return;
    const focusable = [...$("alertDialogForm").querySelectorAll("button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea")].filter(el => el.getClientRects().length);
    const first = focusable[0], last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
  });
  $("alertChannelsBody")?.addEventListener("click", A.run(async event => {
    const test = event.target.closest("[data-alert-test]");
    if (test) return testSend(test);
    const edit = event.target.closest("[data-alert-edit]");
    if (edit) return openEditor(byId(edit.dataset.alertEdit));
    const del = event.target.closest("[data-alert-delete]");
    if (del) return remove(del);
    const retry = event.target.closest("[data-alert-retry]");
    if (retry) return loadChannels();
  }));
  $("alertChannelsBody")?.addEventListener("change", A.run(async event => {
    const input = event.target.closest("[data-alert-toggle]");
    if (input) await toggle(input);
  }));
  $("alertDeliveriesBody")?.addEventListener("click", A.run(async event => {
    if (event.target.closest("[data-alert-retry]")) await loadDeliveries();
  }));

  window.AdminAlerts = { load, loadChannels, loadDeliveries, openEditor };
})();
