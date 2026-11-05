(() => {
  "use strict";
  /* Crypto kill switch and gradual post-quantum rollout (/ui/crypto-switch.html).

     Uses the console's session from localStorage (morrow_token / morrow_refresh) and the
     organization-scoped API under /crypto-switch/... and /pq-rollouts/.... Every state change is
     an explicit admin click; the page itself only reads. No third-party requests. */

  const $ = id => document.getElementById(id);
  const esc = value => String(value ?? "").replace(/[&<>"']/g, ch => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[ch]));
  const store = {
    get: key => { try { return localStorage.getItem(key) || ""; } catch { return ""; } },
    set: (key, value) => { try { localStorage.setItem(key, value); } catch { /* ignore */ } },
    del: key => { try { localStorage.removeItem(key); } catch { /* ignore */ } }
  };
  const STATES = ["vulnerable", "pr_open", "merged", "manual_apply", "rescan_mismatch", "failed", "switched"];
  const LABEL = { vulnerable: "Vulnerable", pr_open: "PR open", merged: "Merged", manual_apply: "Apply by hand",
    rescan_mismatch: "Rescan mismatch", failed: "Failed", switched: "Switched" };
  let openIncident = "";
  let timer = 0;

  function expired(jwt) {
    try {
      const part = String(jwt || "").split(".")[1];
      const payload = JSON.parse(atob(part.replace(/-/g, "+").replace(/_/g, "/")));
      return !payload.exp || payload.exp * 1000 < Date.now() + 5000;
    } catch { return true; }
  }
  async function bearer() {
    let token = store.get("morrow_token");
    if ((!token || expired(token)) && store.get("morrow_refresh")) {
      const r = await fetch("/auth/refresh", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refresh_token: store.get("morrow_refresh") }), cache: "no-store" }).catch(() => null);
      if (r && r.ok) { const d = await r.json().catch(() => ({})); if (d.access_token) { store.set("morrow_token", d.access_token); token = d.access_token; } }
      else if (r && r.status === 401) { store.del("morrow_token"); token = ""; }
    }
    return token && !expired(token) ? token : "";
  }
  async function api(path, { method = "GET", body } = {}) {
    const token = await bearer();
    if (!token) return { ok: false, status: 401, data: null };
    const headers = { Authorization: "Bearer " + token };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    try {
      const res = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), cache: "no-store", credentials: "same-origin" });
      let data = null;
      try { data = await res.json(); } catch { data = null; }
      return { ok: res.ok, status: res.status, data };
    } catch { return { ok: false, status: 0, data: null }; }
  }
  const detail = r => {
    if (r.status === 403) return "Only an organization admin can take this step.";
    const d = r.data && r.data.detail;
    if (typeof d === "string") return d;
    if (d && typeof d === "object") return [d.message, ...(d.refusals || [])].filter(Boolean).join(" ");
    return r.status ? `The server answered ${r.status}.` : "The server could not be reached.";
  };
  const pill = s => `<span class="invite-pill" data-status="${esc(s)}">${esc(LABEL[s] || String(s || "").replace(/_/g, " "))}</span>`;
  const val = id => ($(id) && $(id).value || "").trim();

  async function busy(btn, fn) {
    btn.disabled = true;
    try { await fn(); } finally { btn.disabled = false; }
  }

  // ── Kill switch ────────────────────────────────────────────────────────────────────────────

  function switchBody() {
    return { broken: val("swBroken"), fallback: val("swFallback"), repository: val("swRepo"), reason: val("swReason"),
      batch_size: Number(val("swBatch") || 10), dry_run: $("swDry").checked };
  }

  function planPreview(plan) {
    const pf = plan.preflight || {};
    if (!pf.allowed) return `<div class="notice invite-state" data-tone="bad"><p>Pre-flight refused the fallback.</p><ul>${(pf.refusals || []).map(r => `<li>${esc(r)}</li>`).join("")}</ul></div>`;
    const warn = (pf.warnings || []).map(w => `<p class="sw-note">${esc(w)}</p>`).join("");
    const rows = (plan.items || []).slice(0, 25).map(i => `<tr><td>${esc(i.asset_key)}</td><td>${esc(i.owner || "unassigned")}</td>
      <td>${esc(i.server_type)}</td><td>${esc(String(i.priority).toUpperCase())} · ${esc(i.priority_score)}</td><td>${esc(i.batch)}</td></tr>`).join("");
    return `<div class="sw-card"><div class="sw-head"><span class="sw-name">${esc(pf.broken.name)} &rarr; ${esc(pf.fallback.name)}</span>
      <span class="invite-pill" data-status="completed">pre-flight passed</span></div><p class="sw-note">${esc(plan.summary.affected)} affected assets in ${esc(plan.summary.batches)} batches.
      ${esc(plan.summary.unowned)} without an owner, ${esc(plan.summary.no_repository)} without a linked repository.</p>${warn}
      <table class="sw-table"><thead><tr><th>Asset</th><th>Owner</th><th>Stack</th><th>Priority</th><th>Batch</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }

  function incidentCard(inc, full) {
    const c = inc.counts || {};
    const actions = {
      planned: [["approve", "Approve plan"], ...(inc.dry_run ? [["go-live", "Leave dry run"]] : []), ["cancel", "Cancel"]],
      approved: [["execute", inc.dry_run ? "Preview next batch" : "Open next batch"], ...(inc.dry_run ? [["go-live", "Leave dry run"]] : []), ["cancel", "Cancel"]],
      executing: [["execute", "Open next batch"], ["refresh", "Check requests and rescans"], ["cancel", "Cancel"]],
    }[inc.status] || [];
    const tiles = STATES.map(s => `<div class="sw-tile"><b>${esc(c[s] || 0)}</b><span>${esc(LABEL[s])}</span></div>`).join("");
    const pct = inc.progress ? inc.progress.percent : (c.total ? Math.round(100 * (c.switched || 0) / c.total) : 0);
    let body = "";
    if (full) {
      const cells = (inc.items || []).map(i => `<span class="sw-cell" data-state="${esc(i.state)}" title="${esc(i.asset_key)}: ${esc(LABEL[i.state] || i.state)}"></span>`).join("");
      const rows = (inc.items || []).map(i => `<tr><td>${esc(i.asset_key)}</td><td>${esc(i.owner || "unassigned")}</td><td>${esc(i.server_type)} · batch ${esc(i.batch)}</td>
        <td>${pill(i.state)}${i.note ? `<div class="sw-note">${esc(i.note)}</div>` : ""}</td>
        <td>${i.pr_url ? `<a href="${esc(i.pr_url)}" target="_blank" rel="noopener">request &#8599;</a>` : ""}</td></tr>`).join("");
      const out = inc.batch_result ? `<p class="sw-note">Batch ${esc(inc.batch_result.batch)}: ${(inc.batch_result.requests || []).map(r => `${esc(r.asset_key)} ${esc(r.outcome)}`).join(", ")}</p>` : "";
      body = `<div class="sw-map" aria-label="Assets by state">${cells}</div>${out}
        <table class="sw-table"><thead><tr><th>Asset</th><th>Owner</th><th>Stack</th><th>State</th><th></th></tr></thead><tbody>${rows}</tbody></table>`;
    }
    return `<div class="sw-card" data-incident="${esc(inc.id)}"><div class="sw-head"><span class="sw-name">${esc(inc.broken)} &rarr; ${esc(inc.fallback)}</span>
      <span>${pill(inc.status)} ${inc.dry_run ? pill("dry run") : ""}</span></div>
      <div class="sw-bar" aria-label="${esc(pct)}% switched"><i style="width:${Number(pct) || 0}%"></i></div>
      <div class="sw-tiles">${tiles}</div>${body}
      <div class="sw-actions">${full ? "" : `<button class="btn small" type="button" data-open="${esc(inc.id)}">Live status</button>`}
      ${actions.map(([a, l]) => `<button class="btn small" type="button" data-act="${a}" data-id="${esc(inc.id)}">${esc(l)}</button>`).join("")}</div></div>`;
  }

  async function loadIncidents(message, tone) {
    const r = await api("/crypto-switch/incidents");
    if (r.status === 401) {
      $("swState").innerHTML = `<p>Sign in to use the crypto kill switch.</p><div class="sw-actions"><a class="btn pri" href="/ui/">Sign in</a></div>`;
      $("swState").dataset.tone = "bad";
      $("roSummary").innerHTML = "<p>Sign in to see rollouts.</p>";
      return false;
    }
    $("swForm").hidden = false; $("swFormActions").hidden = false;
    $("swState").innerHTML = `<p>${esc(message || "Declare a break to build an incident plan. Plans start in dry run; an admin approves each step.")}</p>`;
    $("swState").dataset.tone = tone || "";
    const items = (r.data && r.data.items) || [];
    let html = "";
    for (const inc of items) {
      if (inc.id === openIncident) {
        const full = await api(`/crypto-switch/incidents/${encodeURIComponent(inc.id)}`);
        html += incidentCard(full.ok ? full.data : inc, full.ok);
      } else html += incidentCard(inc, false);
    }
    $("swIncidents").innerHTML = html || `<p class="sw-note">No incidents declared.</p>`;
    return true;
  }

  async function incidentAction(btn) {
    const id = btn.dataset.id, act = btn.dataset.act;
    if (act === "cancel" && !window.confirm("Cancel this incident? Open pull requests stay open on your code host.")) return;
    await busy(btn, async () => {
      const r = await api(`/crypto-switch/incidents/${encodeURIComponent(id)}/${act}`, { method: "POST", body: {} });
      openIncident = id;
      if (r.ok && act === "execute") {
        await loadIncidents(r.data.batch_result.dry_run ? "Dry run: these requests would be opened. None were." : "Batch opened.", "ok");
        const card = document.querySelector(`[data-incident="${CSS.escape(id)}"]`);
        if (card) card.outerHTML = incidentCard(r.data, true);
        return;
      }
      await loadIncidents(r.ok ? "Done." : detail(r), r.ok ? "ok" : "bad");
    });
  }

  // ── Rollouts ───────────────────────────────────────────────────────────────────────────────

  function rolloutBody() {
    const platform = val("roPlatform");
    const spec = { service: val("roService"), host: val("roHost") };
    if (platform === "istio") spec.namespace = val("roNs") || "default";
    else { spec.classic_upstream = val("roClassic"); spec.pq_upstream = val("roPq"); }
    return { name: val("roName"), platform, spec, soak_minutes: Number(val("roSoak") || 30), mode: val("roMode"),
      dry_run: $("roDry").checked, repository: val("roRepo"), metrics_token: $("roToken").value,
      metrics: { prometheus_url: val("roProm"), queries: { handshake_failure_rate: val("roQHs"), http_error_rate: val("roQErr") } } };
  }

  function rolloutCard(ro) {
    const stages = (ro.stages || []).map((w, i) => `<span class="sw-stage" data-on="${i < ro.stage_index || ro.status === "completed" ? "done" : i === ro.stage_index ? "now" : ""}">${esc(w)}%</span>`).join("");
    const acts = [];
    if (ro.status === "draft") acts.push(["approve", "Approve rollout"], ["cancel", "Cancel"]);
    if (ro.status === "approved") acts.push(["advance", "Propose first stage"], ["cancel", "Cancel"]);
    if (ro.status === "in_progress") {
      if (ro.stage_state === "awaiting_approval") acts.push(["advance", `Propose ${ro.next_weight}%`]);
      if (["pending_merge", "awaiting_apply"].includes(ro.stage_state)) acts.push(["mark-applied", "Stage is live"]);
      acts.push(["evaluate", "Check gates now"], ["rollback", "Roll back"]);
    }
    const gate = ro.last_gate && ro.last_gate.gates ? ro.last_gate.gates.map(g => `${esc(g.label)}: ${g.pq == null ? "no data" : esc(Number(g.pq).toFixed(4))} vs ${g.baseline == null ? "no data" : esc(Number(g.baseline).toFixed(4))} (${esc(g.result)})`).join(" · ") : "";
    return `<div class="sw-card"><div class="sw-head"><span class="sw-name">${esc(ro.name)} · ${esc(ro.platform)}</span>
      <span>${pill(ro.status)} ${ro.stage_state ? pill(ro.stage_state) : ""} ${ro.dry_run ? pill("dry run") : ""}</span></div>
      <div class="sw-stages">${stages}</div>
      ${ro.rollback_reason ? `<p class="sw-error">Rolled back: ${esc(ro.rollback_reason)}. ${esc(ro.rollback_metric)}</p>` : ""}
      ${gate ? `<p class="sw-note">${gate}</p>` : ""}
      ${ro.pr_url ? `<p class="sw-note"><a href="${esc(ro.pr_url)}" target="_blank" rel="noopener">Current stage request &#8599;</a>${ro.rollback_pr_url ? ` · <a href="${esc(ro.rollback_pr_url)}" target="_blank" rel="noopener">Rollback request &#8599;</a>` : ""}</p>` : ""}
      <div class="sw-actions">${acts.map(([a, l]) => `<button class="btn small" type="button" data-ro="${a}" data-id="${esc(ro.id)}">${esc(l)}</button>`).join("")}</div>
      <div data-ro-out="${esc(ro.id)}"></div></div>`;
  }

  async function loadRollouts(message, tone) {
    const r = await api("/pq-rollouts");
    if (!r.ok) return;
    $("roForm").hidden = false; $("roFormActions").hidden = false;
    $("roSummary").innerHTML = `<p>${esc(message || r.data.summary.text)}</p>`;
    $("roSummary").dataset.tone = tone || "";
    $("roList").innerHTML = (r.data.items || []).map(rolloutCard).join("") || `<p class="sw-note">No rollouts yet.</p>`;
  }

  async function rolloutAction(btn) {
    const id = btn.dataset.id, act = btn.dataset.ro;
    let body = {};
    if (act === "rollback") {
      const reason = window.prompt("Why roll back?", "Rolled back by an administrator");
      if (!reason) return;
      body = { reason };
    }
    await busy(btn, async () => {
      const r = await api(`/pq-rollouts/${encodeURIComponent(id)}/${act}`, { method: "POST", body });
      const tick = r.ok && r.data.tick ? ` Gate check: ${r.data.tick.result}.` : "";
      await loadRollouts(r.ok ? "Done." + tick : detail(r), r.ok ? "ok" : "bad");
      const proposed = r.ok && (r.data.proposed || r.data.rollback);
      if (proposed && proposed.config) {
        const out = document.querySelector(`[data-ro-out="${CSS.escape(id)}"]`);
        if (out) out.innerHTML = `<p class="sw-note">${esc(proposed.outcome === "pr_open" ? "Pull request opened." : "Apply this configuration, then mark the stage live.")}</p><pre class="sw-code">${esc(proposed.config)}</pre>`;
      }
    });
  }

  // ── Wiring ─────────────────────────────────────────────────────────────────────────────────

  async function init() {
    const algs = await api("/crypto-switch/algorithms");
    if (algs.ok) $("swAlgs").innerHTML = [...algs.data.groups, ...algs.data.algorithms].map(a => `<option value="${esc(a.name)}">`).join("");
    const signedIn = await loadIncidents();
    if (!signedIn) return;
    await loadRollouts();
    $("swPreflight").addEventListener("click", e => busy(e.currentTarget, async () => {
      $("swError").textContent = "";
      const r = await api("/crypto-switch/preflight", { method: "POST", body: { broken: val("swBroken"), fallback: val("swFallback") } });
      $("swPreview").innerHTML = r.ok ? planPreview(r.data) : "";
      if (!r.ok) $("swError").textContent = detail(r);
    }));
    $("swDeclare").addEventListener("click", e => busy(e.currentTarget, async () => {
      $("swError").textContent = "";
      const r = await api("/crypto-switch/incidents", { method: "POST", body: switchBody() });
      if (!r.ok) { $("swError").textContent = detail(r); return; }
      openIncident = r.data.id; $("swPreview").innerHTML = "";
      await loadIncidents("Incident declared. Review the plan, then approve it.", "ok");
    }));
    $("swIncidents").addEventListener("click", e => {
      const open = e.target.closest("[data-open]");
      if (open) { openIncident = open.dataset.open; loadIncidents(); return; }
      const act = e.target.closest("[data-act]");
      if (act) incidentAction(act);
    });
    $("roPlatform").addEventListener("change", () => {
      const istio = val("roPlatform") === "istio";
      document.querySelectorAll('[data-for="lb"]').forEach(el => { el.hidden = istio; });
      document.querySelectorAll('[data-for="istio"]').forEach(el => { el.hidden = !istio; });
    });
    $("roPreview").addEventListener("click", e => busy(e.currentTarget, async () => {
      $("roError").textContent = "";
      const b = rolloutBody();
      const r = await api("/pq-rollouts/preview", { method: "POST", body: { name: b.name, platform: b.platform, spec: b.spec } });
      if (!r.ok) { $("roError").textContent = detail(r); $("roPreviewOut").innerHTML = ""; return; }
      $("roPreviewOut").innerHTML = r.data.configs.map(c => `<p class="sw-note">${esc(c.weight)}% to hybrid · ${esc(r.data.file_path)}</p><pre class="sw-code">${esc(c.config)}</pre>`).join("")
        + `<p class="sw-note">Rollback</p><pre class="sw-code">${esc(r.data.rollback)}</pre>`;
    }));
    $("roCreate").addEventListener("click", e => busy(e.currentTarget, async () => {
      $("roError").textContent = "";
      const r = await api("/pq-rollouts", { method: "POST", body: rolloutBody() });
      if (!r.ok) { $("roError").textContent = detail(r); return; }
      $("roToken").value = ""; $("roPreviewOut").innerHTML = "";
      await loadRollouts("Rollout created. An admin approves it before the first stage is proposed.", "ok");
    }));
    $("roList").addEventListener("click", e => { const b = e.target.closest("[data-ro]"); if (b) rolloutAction(b); });
    // Live view: re-read (never write) every 20 seconds while the page is visible.
    timer = window.setInterval(() => { if (!document.hidden) { loadIncidents(); loadRollouts(); } }, 20000);
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init); else init();
  window.addEventListener("beforeunload", () => window.clearInterval(timer));
})();
