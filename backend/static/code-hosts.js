(() => {
  "use strict";
  /* Code hosts page (/ui/code-hosts.html): connect GitHub, GitLab, Bitbucket, Azure DevOps or
     Gitea/Forgejo with an access token, so Morrow can open its fixes as pull requests there.

     Uses the console's session from localStorage (morrow_token / morrow_refresh) and the
     organization-scoped API: GET /code-hosts/providers, GET/POST /code-hosts,
     POST /code-hosts/{id}/test, POST /code-hosts/{id}/default, DELETE /code-hosts/{id}.
     The token is sent once, over this origin, and never shown again. No third-party requests. */

  const $ = id => document.getElementById(id);
  const esc = value => String(value ?? "").replace(/[&<>"']/g, ch => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[ch]));
  const store = {
    get: key => { try { return localStorage.getItem(key) || ""; } catch { return ""; } },
    set: (key, value) => { try { localStorage.setItem(key, value); } catch { /* ignore */ } },
    del: key => { try { localStorage.removeItem(key); } catch { /* ignore */ } }
  };
  let providers = [];
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
    if (d && typeof d === "object") return d.message || "";
    return "";
  };
  const when = iso => { const d = new Date(iso); return Number.isNaN(d.getTime()) ? "never" : d.toLocaleString(); };

  function tokenLink(p, base) {
    const root = (base || p.default_base_url || "").replace(/\/+$/, "");
    if (p.token_url.includes("{base}") && !root) return "";
    return p.token_url.replace("{base}", root);
  }

  function connectForm() {
    const p = providers.find(x => x.id === picked);
    const picks = providers.map(x => `<button class="btn small" type="button" data-pick="${esc(x.id)}" aria-pressed="${x.id === picked}">${esc(x.name)}</button>`).join("");
    if (!p) {
      return `<p>Where does your code live?</p><div class="host-picks">${picks}</div>`;
    }
    const needsUrl = p.self_hosted || !p.default_base_url;
    const link = tokenLink(p, "");
    return `<p>Where does your code live?</p><div class="host-picks">${picks}</div>
      <form class="invite-form" id="hostForm" novalidate>
        ${needsUrl ? `<label>${esc(p.name)} address<input id="hostUrl" type="url" autocomplete="off" spellcheck="false"
            placeholder="${esc(p.default_base_url || p.base_url_hint || "https://")}" value="${esc(p.default_base_url || "")}"></label>` : ""}
        <ol class="host-steps" id="hostSteps">${p.token_steps.map((step, i) => `<li>${i === 0
          ? `<a href="${esc(link || "#")}" target="_blank" rel="noopener" id="hostTokenLink">${esc(step)}</a>` : esc(step)}</li>`).join("")}</ol>
        <label>Access token<input id="hostToken" type="password" autocomplete="off" spellcheck="false" required></label>
        <label>Name (optional)<input id="hostLabel" type="text" maxlength="80" placeholder="${esc(p.name)}"></label>
        <p class="invite-error" id="hostError" role="alert"></p>
        <div class="invite-actions" style="margin-top:0"><button class="btn primary" id="hostConnect" type="submit">Connect ${esc(p.name)}</button></div>
      </form>`;
  }

  function wireForm() {
    $("hostState").querySelectorAll("[data-pick]").forEach(b => b.addEventListener("click", () => { picked = b.dataset.pick; render(); }));
    const url = $("hostUrl");
    if (url) url.addEventListener("input", () => {
      const p = providers.find(x => x.id === picked);
      const a = $("hostTokenLink");
      const link = tokenLink(p, url.value.trim());
      if (a) a.href = link || "#";
    });
    const form = $("hostForm");
    if (!form) return;
    form.addEventListener("submit", async event => {
      event.preventDefault();
      const error = $("hostError"), button = $("hostConnect");
      const token = $("hostToken").value.trim();
      if (!token) { error.textContent = "Paste the access token."; return; }
      button.disabled = true; button.textContent = "Checking the token…"; error.textContent = "";
      const r = await api("/code-hosts", { method: "POST", body: {
        provider: picked, token, base_url: $("hostUrl") ? $("hostUrl").value.trim() : "", label: $("hostLabel").value.trim() } });
      button.disabled = false;
      if (r.ok) { picked = ""; return load(`Connected${r.data.connection.account ? " as " + r.data.connection.account : ""}.`); }
      button.textContent = "Connect";
      error.textContent = r.status === 403 ? "Only an organization admin can connect code hosts." : (detail(r) || `The server answered ${r.status}.`);
    });
  }

  function card(c) {
    return `<article class="dom-card">
      <div class="dom-head">
        <span class="dom-name">${esc(c.label || c.provider_name)}</span>
        <span class="invite-pill" data-status="valid">${c.is_default ? "Default" : esc(c.provider_name)}</span>
      </div>
      <p class="dom-note">${esc(c.provider_name)} · ${esc(c.base_url)}${c.account ? ` · signed in as ${esc(c.account)}` : ""}. Opens ${esc(c.request_name)}s. Last used: ${esc(when(c.last_used_at))}.</p>
      <div class="invite-actions" style="margin-top:4px">
        <button class="btn small" type="button" data-test="${esc(c.id)}">Test</button>
        ${c.is_default ? "" : `<button class="btn small" type="button" data-default="${esc(c.id)}">Make default</button>`}
        <button class="btn small" type="button" data-remove="${esc(c.id)}">Remove</button>
      </div>
    </article>`;
  }

  let connections = [];
  function render(message = "", tone = "") {
    const box = $("hostState");
    box.dataset.tone = tone;
    box.innerHTML = (message ? `<p>${esc(message)}</p>` : "") + connectForm();
    wireForm();
    $("hostList").innerHTML = connections.length ? connections.map(card).join("")
      : `<p class="dom-note">No code host connected yet. Pick yours above; it takes about a minute.</p>`;
  }

  async function load(message = "", tone = "ok") {
    const [p, c] = await Promise.all([api("/code-hosts/providers"), api("/code-hosts")]);
    if (c.status === 401) {
      $("hostState").innerHTML = `<p>Sign in to connect your code host.</p><div class="invite-actions"><a class="btn primary" href="/ui/">Sign in</a></div>`;
      $("hostState").dataset.tone = "bad";
      return;
    }
    if (!p.ok || !c.ok) {
      $("hostState").innerHTML = `<p>${esc(detail(c) || detail(p) || "Code hosts could not be loaded.")}</p>`;
      $("hostState").dataset.tone = "bad";
      return;
    }
    providers = p.data.providers || [];
    connections = c.data.connections || [];
    render(message, message ? tone : "");
  }

  $("hostList").addEventListener("click", async event => {
    const test = event.target.closest("[data-test]");
    if (test) {
      test.disabled = true; test.textContent = "Testing…";
      const r = await api(`/code-hosts/${encodeURIComponent(test.dataset.test)}/test`, { method: "POST" });
      return load(r.ok ? `Working${r.data.account ? ": signed in as " + r.data.account : ""}.` : (detail(r) || `The server answered ${r.status}.`), r.ok ? "ok" : "bad");
    }
    const def = event.target.closest("[data-default]");
    if (def) {
      const r = await api(`/code-hosts/${encodeURIComponent(def.dataset.default)}/default`, { method: "POST" });
      return load(r.ok ? "Default updated." : (detail(r) || `The server answered ${r.status}.`), r.ok ? "ok" : "bad");
    }
    const remove = event.target.closest("[data-remove]");
    if (remove) {
      if (!window.confirm("Remove this connection? Morrow forgets the token. You can also revoke it at your code host.")) return;
      const r = await api(`/code-hosts/${encodeURIComponent(remove.dataset.remove)}`, { method: "DELETE" });
      return load(r.ok ? "Connection removed." : (r.status === 403 ? "Only an organization admin can remove connections." : (detail(r) || `The server answered ${r.status}.`)), r.ok ? "ok" : "bad");
    }
  });

  load();
})();
