(() => {
  "use strict";
  /* Certificate & KMS inventory page (/ui/cert-sources.html): connect certificate managers and
     cloud KMS read-only, test them, sync now or on a schedule, and see what was found.

     Uses the console's session from localStorage (morrow_token / morrow_refresh) and the
     organization-scoped API: GET /cert-sources/providers, GET/POST /cert-sources,
     POST /cert-sources/{id}/test, POST /cert-sources/{id}/sync, PUT /cert-sources/{id}/schedule,
     DELETE /cert-sources/{id}, GET /cert-inventory. Credentials are sent once, over this origin,
     and never shown again. No third-party requests. */

  const $ = id => document.getElementById(id);
  const esc = value => String(value ?? "").replace(/[&<>"']/g, ch => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[ch]));
  const store = {
    get: key => { try { return localStorage.getItem(key) || ""; } catch { return ""; } },
    set: (key, value) => { try { localStorage.setItem(key, value); } catch { /* ignore */ } },
    del: key => { try { localStorage.removeItem(key); } catch { /* ignore */ } }
  };
  const SCHEDULES = [[0, "Off"], [6, "Every 6 hours"], [12, "Every 12 hours"], [24, "Daily"], [168, "Weekly"]];
  let providers = [];
  let connections = [];
  let picked = "";

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
    const d = r.data && r.data.detail;
    if (typeof d === "string") return d;
    if (Array.isArray(d) && d.length) return d.map(x => x.msg || "").filter(Boolean).join("; ");
    if (d && typeof d === "object") return d.message || "";
    return "";
  };
  const when = iso => { if (!iso) return "never"; const d = new Date(iso); return Number.isNaN(d.getTime()) ? "never" : d.toLocaleString(); };
  const day = iso => { if (!iso) return ""; const d = new Date(iso); return Number.isNaN(d.getTime()) ? String(iso) : d.toLocaleDateString(); };

  function field(f) {
    const id = "f_" + f.name;
    const req = f.required ? " required" : "";
    const ph = f.placeholder ? ` placeholder="${esc(f.placeholder)}"` : "";
    let input;
    if (f.type === "select") {
      input = `<select id="${id}" data-field="${esc(f.name)}">${(f.options || []).map(o => `<option value="${esc(o)}">${esc(o.toUpperCase())}</option>`).join("")}</select>`;
    } else if (f.type === "textarea") {
      input = `<textarea id="${id}" data-field="${esc(f.name)}" spellcheck="false" autocomplete="off"${ph}${req}></textarea>`;
    } else {
      const type = f.type === "password" ? "password" : (f.type === "url" ? "url" : "text");
      input = `<input id="${id}" data-field="${esc(f.name)}" type="${type}" autocomplete="off" spellcheck="false"${ph}${req}>`;
    }
    return `<label>${esc(f.label)}${f.required ? "" : " (optional)"}${input}</label>`;
  }

  function connectForm() {
    const p = providers.find(x => x.id === picked);
    const picks = providers.map(x => `<button class="btn small" type="button" data-pick="${esc(x.id)}" aria-pressed="${x.id === picked}">${esc(x.name)}</button>`).join("");
    const head = `<p>What should Morrow read? Certificate managers list certificates; KMS services list key metadata.</p><div class="host-picks">${picks}</div>`;
    if (!p) return head;
    return `${head}
      <form class="invite-form" id="srcForm" novalidate>
        <ol class="host-steps">${p.steps.map(s => `<li>${esc(s)}</li>`).join("")}</ol>
        ${p.fields.map(field).join("")}
        <label>Name (optional)<input id="srcLabel" type="text" maxlength="80" placeholder="${esc(p.name)}"></label>
        <label>Scheduled sync<select id="srcSchedule">${SCHEDULES.map(([h, t]) => `<option value="${h}">${esc(t)}</option>`).join("")}</select></label>
        <p class="dom-note" style="font-size:12.5px">API reference: ${p.docs.map(u => `<a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(new URL(u).hostname)}</a>`).join(", ")}</p>
        <p class="invite-error" id="srcError" role="alert"></p>
        <div class="invite-actions" style="margin-top:0"><button class="btn primary" id="srcConnect" type="submit">Connect ${esc(p.name)}</button></div>
      </form>`;
  }

  function wireForm() {
    $("srcState").querySelectorAll("[data-pick]").forEach(b => b.addEventListener("click", () => { picked = b.dataset.pick; render(); }));
    const form = $("srcForm");
    if (!form) return;
    form.addEventListener("submit", async event => {
      event.preventDefault();
      const error = $("srcError"), button = $("srcConnect");
      const fields = {};
      form.querySelectorAll("[data-field]").forEach(el => { fields[el.dataset.field] = el.value.trim(); });
      button.disabled = true; button.textContent = "Checking the credentials…"; error.textContent = "";
      const r = await api("/cert-sources", { method: "POST", body: {
        provider: picked, fields, label: $("srcLabel").value.trim(), schedule_hours: Number($("srcSchedule").value) } });
      form.querySelectorAll("input[type=password], textarea").forEach(el => { el.value = ""; });
      button.disabled = false;
      if (r.ok) { picked = ""; return load(`Connected${r.data.connection.account ? ": " + r.data.connection.account : ""}. Choose Sync now to read the inventory.`); }
      button.textContent = "Connect";
      error.textContent = r.status === 403 ? "Only an organization admin can add inventory connections." : (detail(r) || `The server answered ${r.status}.`);
    });
  }

  function card(c) {
    const where = c.base_url && !/amazonaws|vault\.azure|googleapis/.test(c.base_url) ? ` · ${esc(c.base_url)}` : "";
    const scope = [c.settings.regions && c.settings.regions.join(", "), c.settings.vault_urls && c.settings.vault_urls.join(", "),
      c.settings.project_id, c.settings.region && c.settings.region.toUpperCase()].filter(Boolean).join(" · ");
    const status = c.last_sync_status || "pending";
    return `<article class="dom-card">
      <div class="dom-head">
        <span class="dom-name">${esc(c.label || c.provider_name)}</span>
        <span class="invite-pill" data-status="${esc(status)}">${esc(status === "pending" ? "Not synced" : status === "ok" ? "Synced" : "Sync failed")}</span>
      </div>
      <p class="dom-note">${esc(c.provider_name)}${where}${scope ? " · " + esc(scope) : ""}${c.account ? ` · ${esc(c.account)}` : ""}.</p>
      <p class="dom-note${status === "error" ? " bad" : ""}">Last sync: ${esc(when(c.last_sync_at))}${c.last_sync_message ? ` — ${esc(c.last_sync_message)}` : ""}.
        ${c.schedule_hours ? `Next scheduled: ${esc(when(c.next_sync_at))}.` : "Scheduled sync is off."}</p>
      <div class="invite-actions" style="margin-top:4px;align-items:center">
        <button class="btn small" type="button" data-sync="${esc(c.id)}">Sync now</button>
        <button class="btn small" type="button" data-test="${esc(c.id)}">Test connection</button>
        <select aria-label="Scheduled sync" data-schedule="${esc(c.id)}">${SCHEDULES.map(([h, t]) => `<option value="${h}"${h === c.schedule_hours ? " selected" : ""}>${esc(t)}</option>`).join("")}</select>
        <button class="btn small" type="button" data-remove="${esc(c.id)}">Remove</button>
      </div>
    </article>`;
  }

  function render(message = "", tone = "") {
    const box = $("srcState");
    box.dataset.tone = tone;
    box.innerHTML = (message ? `<p>${esc(message)}</p>` : "") + connectForm();
    wireForm();
    $("srcList").innerHTML = connections.length ? connections.map(card).join("")
      : `<p class="dom-note">No inventory connection yet. Pick one above.</p>`;
  }

  async function loadInventory() {
    const r = await api("/cert-inventory?limit=500");
    const box = $("invTable");
    if (!r.ok) { box.innerHTML = `<p class="dom-note bad">${esc(detail(r) || "The inventory could not be loaded.")}</p>`; return; }
    const items = r.data.items || [];
    if (!items.length) { box.innerHTML = `<p class="dom-note">Nothing synced yet.</p>`; return; }
    box.innerHTML = `<table class="inv-table"><thead><tr><th>Name</th><th>Source</th><th>Algorithm</th><th>Signature</th><th>Expires</th><th>Owner</th><th>Quantum risk</th><th>Asset</th></tr></thead><tbody>${
      items.map(i => `<tr>
        <td>${esc(i.name || i.subject || i.item_key)}<div class="dom-note" style="font-size:11.5px">${esc(i.kind)}</div></td>
        <td>${esc(i.provider_name)}</td>
        <td class="m">${esc((i.classification && i.classification.algorithm) || i.algorithm)}</td>
        <td class="m">${esc(i.signature_algorithm || "")}</td>
        <td>${esc(day(i.not_after))}</td>
        <td>${esc(i.owner || "")}</td>
        <td><span class="invite-pill" data-status="${esc(i.risk)}">${esc(i.risk)}</span><div class="dom-note" style="font-size:11.5px">${esc((i.classification && i.classification.action) || "")}</div></td>
        <td class="m">${esc(i.asset_key)}${i.linked_tls ? `<div class="dom-note" style="font-size:11.5px">seen by TLS scan</div>` : ""}</td>
      </tr>`).join("")}</tbody></table>`;
  }

  async function load(message = "", tone = "ok") {
    const [p, c] = await Promise.all([api("/cert-sources/providers"), api("/cert-sources")]);
    if (c.status === 401) {
      $("srcState").innerHTML = `<p>Sign in to connect your certificate managers and KMS.</p><div class="invite-actions"><a class="btn primary" href="/ui/">Sign in</a></div>`;
      $("srcState").dataset.tone = "bad";
      return;
    }
    if (!p.ok || !c.ok) {
      $("srcState").innerHTML = `<p>${esc(detail(c) || detail(p) || "Inventory connections could not be loaded.")}</p>`;
      $("srcState").dataset.tone = "bad";
      return;
    }
    providers = p.data.providers || [];
    connections = c.data.connections || [];
    render(message, message ? tone : "");
    loadInventory();
  }

  $("srcList").addEventListener("change", async event => {
    const sel = event.target.closest("[data-schedule]");
    if (!sel) return;
    const r = await api(`/cert-sources/${encodeURIComponent(sel.dataset.schedule)}/schedule`, { method: "PUT", body: { schedule_hours: Number(sel.value) } });
    load(r.ok ? (Number(sel.value) ? "Scheduled sync updated." : "Scheduled sync turned off.") : (r.status === 403 ? "Only an organization admin can change the schedule." : (detail(r) || `The server answered ${r.status}.`)), r.ok ? "ok" : "bad");
  });

  $("srcList").addEventListener("click", async event => {
    const sync = event.target.closest("[data-sync]");
    if (sync) {
      sync.disabled = true; sync.textContent = "Syncing…";
      const r = await api(`/cert-sources/${encodeURIComponent(sync.dataset.sync)}/sync`, { method: "POST" });
      return load(r.ok ? `Synced: ${r.data.message}.` : (detail(r) || `The server answered ${r.status}.`), r.ok ? "ok" : "bad");
    }
    const test = event.target.closest("[data-test]");
    if (test) {
      test.disabled = true; test.textContent = "Testing…";
      const r = await api(`/cert-sources/${encodeURIComponent(test.dataset.test)}/test`, { method: "POST" });
      return load(r.ok ? `Working${r.data.account ? ": " + r.data.account : ""}.` : (detail(r) || `The server answered ${r.status}.`), r.ok ? "ok" : "bad");
    }
    const remove = event.target.closest("[data-remove]");
    if (remove) {
      if (!window.confirm("Remove this connection? Morrow forgets the credentials and drops its certificates and keys from the inventory. Revoke the credential at the vendor too.")) return;
      const r = await api(`/cert-sources/${encodeURIComponent(remove.dataset.remove)}`, { method: "DELETE" });
      return load(r.ok ? "Connection removed." : (r.status === 403 ? "Only an organization admin can remove connections." : (detail(r) || `The server answered ${r.status}.`)), r.ok ? "ok" : "bad");
    }
  });

  load();
})();
