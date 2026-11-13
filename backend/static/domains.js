(() => {
  "use strict";
  /* Domains page (/ui/domains.html): add a domain, publish its TXT record, verify it.

     Uses the console's session from localStorage (morrow_token / morrow_refresh, the console's keys)
     and the organization-scoped API: GET/POST /domains, POST /domains/{d}/verify, DELETE /domains/{d}.
     Team sign-in (admins only): GET /domain-join, PUT /domain-join/{d} {enabled}; anyone with a
     verified mailbox at an enabled domain may join the organization as a viewer (services/team_join.py).
     No third-party requests. */

  const $ = id => document.getElementById(id);
  const esc = value => String(value ?? "").replace(/[&<>"']/g, ch => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[ch]));
  const store = {
    get: key => { try { return localStorage.getItem(key) || ""; } catch { return ""; } },
    set: (key, value) => { try { localStorage.setItem(key, value); } catch { /* ignore */ } },
    del: key => { try { localStorage.removeItem(key); } catch { /* ignore */ } }
  };
  let policy = { enforced: true, unrestricted: false };

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
    if (d && typeof d === "object") return d.message || "";
    return "";
  };
  const when = iso => { const d = new Date(iso); return Number.isNaN(d.getTime()) ? "" : d.toLocaleString(); };

  function notice(html, tone = "") {
    const box = $("domState");
    box.dataset.tone = tone;
    box.innerHTML = html;
  }
  function wireAdd() {
    const form = $("domAdd");
    if (!form) return;
    form.addEventListener("submit", async event => {
      event.preventDefault();
      const input = $("domInput"), error = $("domError"), button = $("domAddBtn");
      const value = input.value.trim();
      if (!value) { error.textContent = "Enter a domain, like example.com."; return; }
      button.disabled = true; error.textContent = "";
      const r = await api("/domains", { method: "POST", body: { domain: value } });
      button.disabled = false;
      if (r.ok) { input.value = ""; return load(); }
      error.textContent = r.status === 403 ? "Only an organization admin or operator can add domains." : (detail(r) || `The server answered ${r.status}.`);
    });
  }

  function card(d) {
    const verified = d.status === "verified";
    const copy = (label, value) => `<button class="btn small" type="button" data-copy="${esc(value)}">Copy ${esc(label)}</button>`;
    return `<article class="dom-card">
      <div class="dom-head">
        <span class="dom-name">${esc(d.domain)}</span>
        <span class="invite-pill" data-status="${verified ? "valid" : "pending"}">${verified ? "Verified" : "Waiting for DNS record"}</span>
      </div>
      ${verified
        ? `<p class="dom-note">Verified ${esc(when(d.verified_at))}. You can scan ${esc(d.domain)} and any name under it.</p>`
        : `<p class="dom-note">Add this record at your DNS provider, then press <b>Check now</b>. New records usually appear within a few minutes.</p>
           <dl class="dom-rec">
             <dt>Type</dt><dd>TXT</dd><span></span>
             <dt>Name</dt><dd>${esc(d.record_name)}</dd>${copy("name", d.record_name)}
             <dt>Value</dt><dd>${esc(d.record_value)}</dd>${copy("value", d.record_value)}
           </dl>
           ${d.last_error ? `<p class="dom-note bad">${esc(d.last_error)}</p>` : ""}`}
      <div class="invite-actions" style="margin-top:4px">
        ${verified ? "" : `<button class="btn primary small" type="button" data-verify="${esc(d.domain)}">Check now</button>`}
        <button class="btn small" type="button" data-remove="${esc(d.domain)}">Remove</button>
      </div>
    </article>`;
  }

  async function load() {
    const r = await api("/domains");
    if (r.status === 401) {
      notice(`<p>Sign in to manage your domains.</p><div class="invite-actions"><a class="btn primary" href="/ui/">Sign in</a></div>`, "bad");
      $("domList").innerHTML = "";
      return;
    }
    if (!r.ok || !r.data) {
      notice(`<p>${esc(detail(r) || "The domains could not be loaded.")}</p><div class="invite-actions"><button class="btn" type="button" id="domRetry">Try again</button></div>`, "bad");
      $("domRetry")?.addEventListener("click", load);
      return;
    }
    policy = { enforced: !!r.data.enforced, unrestricted: !!r.data.unrestricted };
    const scope = !policy.enforced ? "This server doesn't restrict scanning to verified domains."
      : policy.unrestricted ? "Your organization is trusted to scan any host; verifying domains is optional."
      : "You can scan hosts under your verified domains only.";
    notice(`<p>${esc(scope)}</p>
      <form class="invite-form" id="domAdd" novalidate>
        <label>Add a domain<input id="domInput" type="text" inputmode="url" autocomplete="off" spellcheck="false" placeholder="example.com" maxlength="300"></label>
        <p class="invite-error" id="domError" role="alert"></p>
        <div class="invite-actions" style="margin-top:0"><button class="btn primary" id="domAddBtn" type="submit">Add domain</button></div>
      </form>`);
    wireAdd();
    const list = r.data.domains || [];
    $("domList").innerHTML = list.length ? list.map(card).join("") : `<p class="dom-note">No domains yet. Add the domain your servers live under, for example the one in your email address.</p>`;
    await loadJoin();
  }

  // ---------- team sign-in ----------
  async function loadJoin() {
    const box = $("joinBox");
    if (!box) return;
    const r = await api("/domain-join");
    if (r.status === 403 || r.status === 401 || r.status === 404) { box.hidden = true; return; }   // admins only
    box.hidden = false;
    if (!r.ok || !r.data) { box.innerHTML = `<p class="dom-note bad">${esc(detail(r) || "Team sign-in settings could not be loaded.")}</p>`; return; }
    const policies = r.data.policies || [];
    const joined = r.data.joined || [];
    const rows = policies.filter(p => p.verified).map(p => {
      const why = p.free_mail ? "Free email providers can't be used."
        : p.claimed_by_other_organization ? "Another organization verified this domain first."
        : p.enabled ? `Anyone with a verified mailbox @${p.domain} can join as a viewer at /join.`
        : `Off. People @${p.domain} need an invitation.`;
      const canEnable = !p.free_mail && !p.claimed_by_other_organization;
      return `<article class="dom-card">
        <div class="dom-head"><span class="dom-name">@${esc(p.domain)}</span>
          <span class="invite-pill" data-status="${p.enabled ? "valid" : "pending"}">${p.enabled ? "Team sign-in on" : "Team sign-in off"}</span></div>
        <p class="dom-note">${esc(why)}</p>
        <div class="invite-actions" style="margin-top:4px">
          ${p.enabled ? `<button class="btn small" type="button" data-join-off="${esc(p.domain)}">Turn off</button>`
            : canEnable && r.data.available ? `<button class="btn primary small" type="button" data-join-on="${esc(p.domain)}">Let @${esc(p.domain)} join</button>` : ""}
        </div></article>`;
    }).join("");
    box.innerHTML = `<h2>Team sign-in</h2>
      <p class="dom-note">${r.data.available ? "Let colleagues join without an invitation: they enter their work email at <b>/join</b>, open the emailed link and create a passkey. They start as viewers. The DNS record is checked again on every join, so removing it pauses joining."
        : r.data.invite_links_available ? "Morrow doesn't email join links on this server. Invite people with an invite link instead: in the console, Administration, Users &amp; access, Invite link. They open it, create a passkey and join as viewers."
        : "Team sign-in needs passkeys and email, which aren't set up on this server."}</p>
      ${rows || `<p class="dom-note">Verify a domain above first.</p>`}
      <p class="invite-error" id="joinError" role="alert"></p>
      <h3 style="margin-top:22px">Joined through team sign-in</h3>
      ${joined.length ? `<dl class="dom-rec">${joined.map(j => `<dt>${esc(when(j.joined_at))}</dt><dd>${esc(j.email || (j.domain ? "" : "invite link"))}</dd><span>${esc(j.role)}</span>`).join("")}</dl>`
        : `<p class="dom-note">Nobody yet.</p>`}`;
  }
  async function setJoin(domain, enabled, button) {
    button.disabled = true;
    const r = await api(`/domain-join/${encodeURIComponent(domain)}`, { method: "PUT", body: { enabled } });
    button.disabled = false;
    if (!r.ok) { const e = $("joinError"); if (e) e.textContent = detail(r) || `The server answered ${r.status}.`; return; }
    return loadJoin();
  }

  $("joinBox")?.addEventListener("click", async event => {
    const on = event.target.closest("[data-join-on]");
    if (on) {
      if (!window.confirm(`Let anyone with a verified @${on.dataset.joinOn} email address join your organization as a viewer?`)) return;
      return setJoin(on.dataset.joinOn, true, on);
    }
    const off = event.target.closest("[data-join-off]");
    if (off) return setJoin(off.dataset.joinOff, false, off);
  });

  $("domList").addEventListener("click", async event => {
    const copy = event.target.closest("[data-copy]");
    if (copy) {
      try { await navigator.clipboard.writeText(copy.dataset.copy); copy.textContent = "Copied"; setTimeout(() => load(), 1200); } catch { /* clipboard blocked: the value is on screen */ }
      return;
    }
    const verify = event.target.closest("[data-verify]");
    if (verify) {
      verify.disabled = true; verify.textContent = "Checking…";
      const r = await api(`/domains/${encodeURIComponent(verify.dataset.verify)}/verify`, { method: "POST" });
      if (!r.ok && r.status !== 0) { notice(`<p>${esc(detail(r) || `The server answered ${r.status}.`)}</p>`, "bad"); setTimeout(load, 2500); return; }
      return load();
    }
    const remove = event.target.closest("[data-remove]");
    if (remove) {
      if (!window.confirm(`Remove ${remove.dataset.remove}? You won't be able to scan it until you verify it again.`)) return;
      const r = await api(`/domains/${encodeURIComponent(remove.dataset.remove)}`, { method: "DELETE" });
      if (!r.ok) { notice(`<p>${esc(r.status === 403 ? "Only an organization admin can remove domains." : (detail(r) || `The server answered ${r.status}.`))}</p>`, "bad"); setTimeout(load, 2500); return; }
      return load();
    }
  });

  load();
})();
