/* Display links for wall mode (services/display_links.py). Mounted by the console's
   Administration view into #wallLinks. Uses the console's api client (safe, H). A display link
   opens /wall on an office screen with no sign-in; it reads one sentence and one number, nothing else. */
(function () {
  "use strict";
  const when = iso => {
    if (!iso) return "";
    const d = new Date(iso);
    return isNaN(d) ? "" : d.toLocaleString(undefined, { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
  };
  const expiryLabel = n => n ? (n === 1 ? "1 day" : `${n} days`) : "Never";
  const statusPill = s => `<span class="pill ${s === "active" ? "ok" : ""}">${s === "active" ? "Working" : s === "revoked" ? "Revoked" : "Expired"}</span>`;

  function row(l, numbers) {
    const live = l.status === "active";
    const pick = live ? `<label class="srOnly" for="wl-m-${H(l.id)}">Number for ${H(l.name)}</label>
      <select class="inp wl-metric" id="wl-m-${H(l.id)}" data-id="${H(l.id)}">${numbers.map(n =>
        `<option value="${H(n.id)}"${n.id === l.metric ? " selected" : ""}>${H(n.label)}</option>`).join("")}</select>`
      : H(l.metric_label || l.metric);
    return `<tr>
      <td><b>${H(l.name)}</b><span class="sub">${statusPill(l.status)}</span></td>
      <td>${pick}</td>
      <td><span class="sub">${H(l.created_by || "")}</span><span class="sub">${H(when(l.created_at))}</span></td>
      <td><span class="sub">${l.last_used_at ? H(when(l.last_used_at)) : "Not opened yet"}</span></td>
      <td><span class="sub">${l.revoked_at ? `Revoked ${H(when(l.revoked_at))}` : l.expires_at ? H(when(l.expires_at)) : "Never"}</span></td>
      <td>${live ? `<button type="button" class="btn xs wl-revoke" data-id="${H(l.id)}" data-name="${H(l.name)}">Revoke</button>` : ""}</td>
    </tr>`;
  }

  async function mount(host) {
    if (!host) return;
    host.innerHTML = `<p class="sub" role="status">Loading display links…</p>`;
    const r = await safe("/display-links");
    if (!host.isConnected) return;
    if (!r.ok) {
      host.innerHTML = `<div class="card"><div class="cardBody"><p>Display links could not load: ${H(r.err)}</p>
        <p class="sub">Only an admin or owner of the organization can see and make them.</p></div></div>`;
      return;
    }
    const v = r.data, links = v.links || [], numbers = v.numbers || [];
    host.innerHTML = `<div class="card"><div class="cardHead"><div class="grow"><h3>Display links</h3>
        <p>Put Morrow on an office screen without signing in on it. The screen shows your risk sentence and one number, and refreshes every minute. A link can read nothing else.</p></div></div>
      <div class="cardBody">
        <form class="row" id="wlForm" style="flex-wrap:wrap;gap:10px;align-items:flex-end">
          <div class="field"><label for="wlName">Screen name</label><input class="inp" id="wlName" maxlength="80" placeholder="Office screen, 3rd floor"></div>
          <div class="field"><label for="wlMetric">Number</label><select class="inp" id="wlMetric">${numbers.map(n =>
            `<option value="${H(n.id)}">${H(n.label)}</option>`).join("")}</select></div>
          <div class="field"><label for="wlExpiry">Expires after</label><select class="inp" id="wlExpiry">${(v.expiry_days || [0]).map(n =>
            `<option value="${n}">${H(expiryLabel(n))}</option>`).join("")}</select></div>
          <div class="field"><label for="wlTheme">Screen</label><select class="inp" id="wlTheme"><option value="dark">Dark</option><option value="light">Light</option></select></div>
          <button type="submit" class="btn sm pri" id="wlCreate">Make display link</button>
        </form>
        <p class="sub" id="wlHelp">${numbers.map(n => `<b>${H(n.label)}:</b> ${H(n.help)}`).join(" ")}</p>
        <div id="wlNew" role="status" aria-live="polite"></div>
        ${links.length ? `<div class="tw" tabindex="0" role="region" aria-label="Display links"><table><thead><tr><th>Screen</th><th>Number</th><th>Made by</th><th>Last used</th><th>Expires</th><th></th></tr></thead>
          <tbody>${links.map(l => row(l, numbers)).join("")}</tbody></table></div>`
          : `<p class="sub">No display links yet.</p>`}
        <p class="sub" id="wlMsg" role="status" aria-live="polite"></p>
      </div></div>`;
    const msg = t => { const m = host.querySelector("#wlMsg"); if (m) m.textContent = t; };

    host.querySelector("#wlForm").addEventListener("submit", async ev => {
      ev.preventDefault();
      const btn = host.querySelector("#wlCreate");
      btn.disabled = true;
      const res = await safe("/display-links", { method: "POST", body: {
        name: host.querySelector("#wlName").value, metric: host.querySelector("#wlMetric").value,
        expires_in_days: Number(host.querySelector("#wlExpiry").value) || 0 } });
      btn.disabled = false;
      if (!res.ok) { msg(`The link was not made: ${res.err}`); return; }
      const light = host.querySelector("#wlTheme").value === "light";
      const base = res.data.url && /^https?:/.test(res.data.url) ? res.data.url : `${location.origin}/wall#t=${res.data.token}`;
      const url = base + (light ? "&theme=light" : "");
      await mount(host);
      const box = host.querySelector("#wlNew");
      box.innerHTML = `<div class="banner info" style="margin:12px 0"><div>
        <b>Open this on the screen.</b> It is shown only now; Morrow keeps only a fingerprint of it. Anyone with the link sees what the screen sees.
        <div class="row" style="margin-top:8px;gap:8px;flex-wrap:wrap"><input class="inp mono" id="wlUrl" readonly value="${H(url)}" aria-label="Display link" style="flex:1;min-width:220px">
        <button type="button" class="btn sm" id="wlCopy">Copy</button></div></div></div>`;
      box.querySelector("#wlCopy").addEventListener("click", async () => {
        try { await navigator.clipboard.writeText(url); msg("Copied."); }
        catch { box.querySelector("#wlUrl").select(); msg("Select the link and copy it."); }
      });
    });

    host.querySelectorAll(".wl-metric").forEach(sel => sel.addEventListener("change", async () => {
      const res = await safe(`/display-links/${encodeURIComponent(sel.dataset.id)}`, { method: "PATCH", body: { metric: sel.value } });
      msg(res.ok ? "Saved. The screen changes at its next refresh." : `Not saved: ${res.err}`);
    }));

    host.querySelectorAll(".wl-revoke").forEach(b => b.addEventListener("click", async () => {
      if (!window.confirm(`Revoke "${b.dataset.name}"? The screen stops showing data at its next refresh.`)) return;
      b.disabled = true;
      const res = await safe(`/display-links/${encodeURIComponent(b.dataset.id)}`, { method: "DELETE" });
      if (!res.ok) { b.disabled = false; msg(`Not revoked: ${res.err}`); return; }
      await mount(host);
      msg("Revoked.");
    }));
  }

  window.wallLinksMount = mount;
})();
