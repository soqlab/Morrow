/* Quantum fire drill: "algorithm X was broken this morning — how long until we are safe?"
   Mounted by the console's Remediation view into #fireDrill. Uses the console's api client
   (safe, H). Everything a drill does is a dry run on the server (services/fire_drill.py). */
(function () {
  "use strict";
  const days = n => n === 1 ? "1 day" : `${n} days`;
  const up = v => Math.ceil(Number(v) || 0);
  const when = iso => {
    const d = new Date(iso);
    return isNaN(d) ? "" : d.toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });
  };
  const how = lane => {
    if (lane.kind === "vendor_wait") return "waiting for the vendor";
    const parts = [];
    if (lane.automated) parts.push(`${lane.automated} by pull request`);
    if (lane.manual) parts.push(`${lane.manual} by hand`);
    if (lane.vendor_setting) parts.push(`${lane.vendor_setting} vendor setting${lane.vendor_setting === 1 ? "" : "s"}`);
    return parts.join(", ");
  };

  function headline(d) {
    if (!d) return `<p class="fd-sentence">No drill has run yet. A drill plans the kill switch against your inventory, changes nothing, and tells you how long the move would take.</p>`;
    if (d.status !== "ok") {
      const why = (d.refusals || []).map(r => `<li>${H(r)}</li>`).join("");
      return `<p class="fd-sentence">${H(d.summary || "")}</p>${why ? `<ul class="fd-list">${why}</ul>` : ""}`;
    }
    const lo = up(d.days.low), hi = up(d.days.high), n = d.time_to_safe_days;
    const trend = d.trend ? `<span class="fd-trend fd-${H(d.trend.direction)}">${H(d.trend.label)}</span>` : "";
    return `<p class="fd-sentence">${H(d.summary)}</p>
      <div class="fd-number">
        <b>${n < 1 ? "&lt;1" : H(String(n))}</b><span class="fd-unit">${n === 1 ? "day" : "days"} to safe</span>
        ${lo !== hi ? `<span class="fd-range">range ${H(String(lo))}–${H(days(hi))}</span>` : ""}
        ${trend}
      </div>`;
  }

  function breakdown(d) {
    if (!d || d.status !== "ok" || !d.affected) {
      const gaps = (d && d.gaps) || [];
      return gaps.length ? `<h4>What Morrow does not know</h4><ul class="fd-list">${gaps.map(g => `<li>${H(g)}</li>`).join("")}</ul>` : "";
    }
    const p = d.paths || {};
    const lanes = (d.lanes || []).map(l => `<li class="fd-lane">
        <div class="fd-lane-head"><b>${H(l.label)}</b><span>${H(String(l.assets))} asset${l.assets === 1 ? "" : "s"} · ${H(how(l))}</span></div>
        <div class="fd-lane-days"><b>${H(days(up(l.days.likely)))}</b><span>${H(String(up(l.days.low)))}–${H(String(up(l.days.high)))}</span></div>
        <p class="fd-basis">${l.measured ? "" : "<span class=\"fd-tag\">assumed</span> "}${H(l.basis)}</p>
      </li>`).join("");
    const list = (title, items) => items && items.length
      ? `<h4>${H(title)}</h4><ul class="fd-list">${items.map(x => `<li>${H(x)}</li>`).join("")}</ul>` : "";
    return `<p class="fd-paths">${H(String(d.affected))} affected: ${H(String(p.automated || 0))} by pull request,
        ${H(String(p.manual || 0))} by hand, ${H(String((p.vendor_setting || 0) + (p.vendor_wait || 0)))} at a vendor.
        Fallback: <span class="mono">${H(d.fallback || "")}</span>.</p>
      <h4>Slowest first</h4><ul class="fd-lanes">${lanes}</ul>
      ${list("What Morrow does not know", d.gaps)}
      ${list("Assumptions", d.assumptions)}
      ${list("Pre-flight warnings", d.warnings)}
      <p class="fd-model">${H(d.model || "")}</p>`;
  }

  function history(rows) {
    const past = (rows || []).slice(1, 7);
    if (!past.length) return "";
    return `<h4>Earlier drills</h4><ul class="fd-history">${past.map(r => `<li><span>${H(when(r.created_at))}</span>
      <span>${H(r.broken)}</span><b>${r.time_to_safe_days == null ? "—" : H(days(r.time_to_safe_days))}</b></li>`).join("")}</ul>`;
  }

  function controls(v) {
    const s = v.schedule || {};
    const algos = v.algorithms || [];
    const next = s.cadence !== "off" && s.next_run_at ? `Next drill ${H(when(s.next_run_at))}, ${H(s.broken)}.` : "No drill is scheduled.";
    if (!v.can_run) return `<p class="fd-note">${next} Admins run drills and set the schedule.</p>`;
    const opt = (val, label, cur) => `<option value="${H(val)}"${val === cur ? " selected" : ""}>${H(label)}</option>`;
    const current = (v.latest && v.latest.broken) || s.broken || "X25519";
    return `<div class="fd-controls">
        <label>Algorithm that broke<select id="fdAlgo">${algos.map(a => opt(a.name, a.label, current)).join("")}</select></label>
        <button type="button" class="btn sm pri" id="fdRun">Run a drill now</button>
      </div>
      <div class="fd-controls">
        <label>Repeat<select id="fdCadence">${["off", "monthly", "quarterly"].map(c => opt(c, c === "off" ? "Off" : c[0].toUpperCase() + c.slice(1), s.cadence || "off")).join("")}</select></label>
        <button type="button" class="btn sm" id="fdSave">Save schedule</button>
        <span class="fd-note">${next}</span>
      </div>`;
  }

  async function mount(host) {
    if (!host) return;
    host.innerHTML = `<section class="card fd" aria-labelledby="fdTitle"><div class="cardBody"><p class="fd-note" role="status">Loading the fire drill…</p></div></section>`;
    const r = await safe("/fire-drills");
    if (!host.isConnected) return;
    if (!r.ok) {
      host.innerHTML = `<section class="card fd" aria-labelledby="fdTitle"><div class="cardBody"><h3 id="fdTitle">Quantum fire drill</h3><p class="fd-note">The fire drill could not load: ${H(r.err)}</p></div></section>`;
      return;
    }
    const v = r.data, d = v.latest;
    const meta = d ? `<p class="fd-note">${H(d.broken)} drill, ${H(when(d.created_at))}${d.trigger === "scheduled" ? ", on schedule" : ""}. Dry run: nothing was changed or sent.</p>` : "";
    host.innerHTML = `<section class="card fd" aria-labelledby="fdTitle">
      <div class="cardHead"><div class="grow"><h3 id="fdTitle">Quantum fire drill</h3>
        <p>If an algorithm broke this morning, how long until you are safe?</p></div></div>
      <div class="cardBody">
        ${headline(d)}
        ${meta}
        ${d && d.status === "ok" && d.affected ? `<details class="fd-details"><summary>How this number was worked out</summary>${breakdown(d)}</details>` : breakdown(d)}
        ${history(v.history)}
        ${controls(v)}
        <p class="fd-note" id="fdMsg" role="status" aria-live="polite"></p>
      </div></section>`;
    const msg = t => { const m = host.querySelector("#fdMsg"); if (m) m.textContent = t; };
    const run = host.querySelector("#fdRun");
    if (run) run.addEventListener("click", async () => {
      run.disabled = true; msg("Running the drill. Nothing will be changed…");
      const res = await safe("/fire-drills", { method: "POST", body: { broken: host.querySelector("#fdAlgo").value } });
      run.disabled = false;
      if (!res.ok) { msg(`The drill did not run: ${res.err}`); return; }
      await mount(host);
      msg("Drill finished.");
    });
    const save = host.querySelector("#fdSave");
    if (save) save.addEventListener("click", async () => {
      save.disabled = true;
      const res = await safe("/fire-drills/schedule", { method: "PUT", body: {
        cadence: host.querySelector("#fdCadence").value, broken: host.querySelector("#fdAlgo").value } });
      save.disabled = false;
      if (!res.ok) { msg(`The schedule was not saved: ${res.err}`); return; }
      await mount(host);
      msg(res.data.cadence === "off" ? "Scheduled drills are off." : `Saved. Next drill ${when(res.data.next_run_at)}.`);
    });
  }

  window.fireDrillMount = mount;
})();
