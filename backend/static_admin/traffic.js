const keyInput = document.getElementById("platformKey");
    const roleInput = document.getElementById("platformRole");
    const apiState = document.getElementById("apiState");
    const statusEl = document.getElementById("status");
    const liveBtn = document.getElementById("liveBtn");
    const fmt = new Intl.NumberFormat();
    let liveTimer = null;
    let refreshing = false;
    let refreshVersion = 0;
    const historySource = () => document.getElementById("historySource").value;
    const filterQuery = () => new URLSearchParams({ source: historySource(), source_ip: document.getElementById("ipFilter").value.trim(), path_prefix: document.getElementById("pathFilter").value.trim() }).toString();

    ["pqc_platform_admin_key", "pqc_platform_key", "pqc_platform_admin_role"].forEach(name => localStorage.removeItem(name));
    keyInput.value = sessionStorage.getItem("pqc_platform_admin_key") || "";
    roleInput.value = sessionStorage.getItem("pqc_platform_admin_role") || "owner";
    function applyRoleControls() {
      const clear = document.getElementById("clearTrafficBtn");
      clear.disabled = !["owner", "operator"].includes(roleInput.value);
      clear.title = clear.disabled ? "The owner or operator role is required to clear traffic." : "";
    }
    roleInput.addEventListener("change", applyRoleControls);
    applyRoleControls();

    // SSO sign-in (admin-auth.js on /vendor-admin/) leaves an HttpOnly session cookie and a readable CSRF
    // cookie. When that session exists, Traffic Lens uses it: no key is sent or stored, writes carry the
    // CSRF token from /platform/whoami, and a session still waiting for MFA goes back to the console.
    const sessionAuth = { active: false, csrf: "", who: null };
    const csrfCookie = () => document.cookie.split("; ").some(c => c.startsWith("pqc_admin_csrf="));
    function lockRoles(who){
      const allowed = Array.isArray(who.allowed_roles) && who.allowed_roles.length ? who.allowed_roles : ["owner", "operator", "support", "auditor"];
      [...roleInput.options].forEach(option => { option.disabled = !allowed.includes(option.value); });
      if (!allowed.includes(roleInput.value)) roleInput.value = allowed[0];
      applyRoleControls();
      return allowed;
    }
    function mfaPending(who){
      const mfa = (who && who.mfa) || {};
      return !mfa.elevated && !!(mfa.enrolled || mfa.required);
    }
    async function detectSession(){
      if (keyInput.value.trim() || !csrfCookie()) return false;
      let res;
      try { res = await fetch("/platform/whoami", { cache:"no-store", credentials:"same-origin", signal:AbortSignal.timeout(15000) }); }
      catch { return false; }
      if (!res.ok) {
        setStatus(res.status === 401 ? "Your console session ended. Sign in again at /vendor-admin/, or enter a named operator key." : `Session check failed (${res.status}). Enter a platform key.`, "bad");
        return false;
      }
      const who = await res.json().catch(() => ({}));
      if (who.credential_source !== "operator_session") return false;
      if (mfaPending(who)) {
        setStatus("Finish signing in (MFA) in the operator console. Redirecting...", "bad");
        location.replace("/vendor-admin/");
        return false;
      }
      sessionAuth.active = true; sessionAuth.csrf = String(who.csrf_token || ""); sessionAuth.who = who;
      keyInput.value = ""; keyInput.disabled = true; keyInput.placeholder = "Signed in with SSO";
      roleInput.value = who.role || roleInput.value;
      lockRoles(who);
      document.getElementById("saveBtn").hidden = true;
      document.body.dataset.auth = "session";
      setStatus(`Signed in as ${who.email || who.operator} (${who.auth_method === "sso" ? "SSO" : "operator"} session). Nothing is stored in this tab.`, "ok");
      return true;
    }

    // Named operator keys carry their own role: lock the picker to it. The shared key keeps the picker,
    // limited to roles within its ceiling.
    let identityCheckedFor = "";
    async function ensureIdentity(key){
      if (!key || identityCheckedFor === key) return;
      identityCheckedFor = key;
      try {
        const res = await fetch("/platform/whoami", { cache:"no-store", signal:AbortSignal.timeout(15000), headers:{ "x-platform-key": key } });
        if (!res.ok) { identityCheckedFor = ""; return; }
        const who = await res.json();
        const allowed = lockRoles(who);
        if (who.role_bound) { roleInput.value = who.role; roleInput.disabled = true; }
        else { roleInput.disabled = false; if (!allowed.includes(roleInput.value)) roleInput.value = allowed[0]; }
        roleInput.title = who.role_bound ? `Role bound to operator ${who.operator}` : "";
        applyRoleControls();
      } catch { identityCheckedFor = ""; }
    }

    function esc(value){
      return String(value ?? "").replace(/[&<>"']/g, ch => ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;" }[ch]));
    }
    function setStatus(text, kind=""){
      statusEl.textContent = text;
      statusEl.className = "status " + kind;
      apiState.textContent = kind === "ok" ? "Connected" : kind === "bad" ? "Blocked" : "Waiting";
      apiState.className = "pill " + (kind === "ok" ? "ok" : kind === "bad" ? "bad" : "");
    }
    function authHeaders(method="GET"){
      if (sessionAuth.active) {
        const headers = { "x-platform-admin-role": roleInput.value || sessionAuth.who?.role || "auditor" };
        if (!["GET", "HEAD"].includes(String(method).toUpperCase())) headers["x-csrf-token"] = sessionAuth.csrf;
        return headers;
      }
      const key = keyInput.value.trim();
      if(!key) throw new Error("Missing platform admin key");
      return { "x-platform-key": key, "x-platform-admin-role": roleInput.value || "owner" };
    }
    function failure(res, body){
      const detail = body && body.detail;
      const code = detail && typeof detail === "object" ? detail.code || "" : "";
      if (sessionAuth.active && res.status === 401 && /^mfa_/.test(code)) location.replace("/vendor-admin/");
      const error = new Error(detail && typeof detail === "object" ? detail.message || code || `${res.status}` : detail || `${res.status} ${res.statusText}`);
      error.status = res.status; error.code = code;
      return error;
    }
    async function api(path, opts={}){
      const headers = authHeaders(opts.method);
      if (!sessionAuth.active) await ensureIdentity(keyInput.value.trim());
      const res = await fetch(path, { ...opts, cache:"no-store", credentials:"same-origin", signal:AbortSignal.timeout(30000), headers:{ ...headers, ...(opts.headers || {}) } });
      const text = await res.text();
      let body = {};
      try{ body = text ? JSON.parse(text) : {}; }catch{ body = { detail:text }; }
      if(!res.ok) throw failure(res, body);
      return body;
    }
    function metric(id, value){ document.getElementById(id).textContent = value == null ? "--" : fmt.format(Number(value)); }
    function pill(value, kind=""){
      return `<span class="pill ${kind}">${esc(value)}</span>`;
    }
    function statusCell(code){
      const n = Number(code || 0);
      const kind = n >= 500 ? "bad" : n === 429 || n === 401 || n === 403 ? "warn" : n >= 200 && n < 400 ? "ok" : "";
      return pill(n || "unknown", kind);
    }
    function latencyCell(ms){
      const n = Number(ms || 0);
      const kind = n >= 1000 ? "bad" : n >= 400 ? "warn" : "ok";
      return pill(`${n}ms`, kind);
    }
    function renderBars(container, obj){
      const entries = Array.isArray(obj) ? obj : Object.entries(obj || {}).map(([label,count]) => ({ label, count }));
      const max = Math.max(1, ...entries.map(x => Number(x.count || 0)));
      container.innerHTML = entries.length ? entries.map(item => `
        <div class="event"><b>${esc(item.label || item.path)}</b><span>${fmt.format(Number(item.count || 0))} requests</span><div class="bar"><i style="width:${Math.max(4, Math.round((Number(item.count || 0) / max) * 100))}%"></i></div></div>
      `).join("") : `<div class="event"><span>No data in buffer.</span></div>`;
    }
    function renderIps(items){
      const body = document.getElementById("ipsBody");
      body.innerHTML = (items || []).length ? items.map(item => {
        const paths = (item.top_paths || []).slice(0,3).map(p => `${esc(p.path)} (${fmt.format(p.count)})`).join("<br>");
        return `<tr>
          <td class="mono">${esc(item.source_ip)}<div class="muted">${esc(item.ip_hash)}</div></td>
          <td>${fmt.format(item.requests)}</td>
          <td>${fmt.format(item.blocked)}</td>
          <td>${fmt.format(item.rate_limited)}</td>
          <td>${fmt.format(item.errors)}</td>
          <td>${fmt.format(item.slow)}</td>
          <td>${paths || "<span class='muted'>none</span>"}</td>
          <td class="mono">${esc(item.last_seen)}</td>
        </tr>`;
      }).join("") : `<tr><td colspan="8" class="muted">No traffic captured yet.</td></tr>`;
    }
    function renderEvents(items){
      const body = document.getElementById("eventsBody");
      body.innerHTML = (items || []).length ? items.map(item => `<tr>
        <td class="mono">${esc(item.created_at)}</td>
        <td class="mono">${esc(item.source_ip)}</td>
        <td>${esc(item.method)}</td>
        <td class="mono">${esc(item.path)}</td>
          <td>${statusCell(item.status_code)}</td>
          <td>${latencyCell(item.duration_ms)}</td>
        <td class="mono">${esc(item.organization_id)}</td>
        <td>${esc(item.authenticated ? item.actor_role || "authenticated" : "Unverified / anonymous")}<div class="muted">${esc(item.actor_id || "")}</div></td>
        <td>${esc(item.user_agent || "")}</td>
      </tr>`).join("") : `<tr><td colspan="9" class="muted">No matching events.</td></tr>`;
    }
    function renderPolicy(policy){
      const publicItems = (policy.public_no_login || []).slice(0,8).map(x => `<div class="event"><b>${esc(x.path)}</b><span>${esc(x.purpose)}</span></div>`).join("");
      document.getElementById("policyBody").innerHTML = `
        <div class="event"><b>Rule</b><span>${esc(policy.principle || "")}</span></div>
        ${publicItems}
        <div class="event"><b>Admin</b><span>${esc(policy.admin_rule || "")}</span></div>`;
    }
    async function loadPolicy(){
      try{
        const res = await fetch("/auth/access-policy");
        renderPolicy(await res.json());
      }catch{
        document.getElementById("policyBody").innerHTML = `<div class="event"><span>Access policy is unavailable.</span></div>`;
      }
    }
    async function loadTraffic(){
      if (refreshing) return;
      refreshing = true;
      document.getElementById("refreshBtn").disabled = true;
      const version = ++refreshVersion;
      try {
      setStatus("Loading traffic...", "");
      const summary = await api("/platform/traffic/summary?limit=80");
      metric("mEvents", summary.totals?.events_in_buffer);
      metric("mIps", summary.totals?.unique_ips);
      metric("mBlocked", summary.totals?.blocked);
      metric("mRate", summary.totals?.rate_limited);
      metric("mErrors", summary.totals?.errors);
      metric("mSlow", summary.totals?.slow);
      document.getElementById("proxyState").textContent = summary.trust_proxy_headers ? "proxy headers trusted" : "direct client IP, proxy headers off";
      renderIps(summary.top_ips || []);
      renderBars(document.getElementById("statusBody"), summary.status_breakdown || {});
      renderBars(document.getElementById("pathsBody"), summary.top_paths || []);
      if (historySource() === "archive" || document.getElementById("ipFilter").value.trim() || document.getElementById("pathFilter").value.trim()) await loadEvents();
      else if (version === refreshVersion) renderEvents(summary.recent_events || []);
      const storage = summary.persistent_storage || {};
      const healthy = storage.enabled && storage.status === "available";
      document.getElementById("retentionState").textContent = `Archive: ${storage.enabled ? storage.status || "unknown" : "disabled"} (${storage.backend || "unknown"}); retention ${storage.traffic_retention_days ?? "unknown"} days. Summaries cover this process only. Clear Buffer leaves retained history intact.`;
      setStatus(`Snapshot ${new Date().toLocaleTimeString()} - ${summary.totals?.events_in_buffer ?? "unknown"} buffered events. ${healthy ? "Database history available." : "Warning: durable logging is disabled or degraded."}`, healthy ? "ok" : "bad");
      } finally { refreshing = false; document.getElementById("refreshBtn").disabled = false; }
    }
    async function loadEvents(){
      const version = ++refreshVersion;
      let events;
      try { events = await api(`/platform/traffic/events?limit=200&${filterQuery()}`); }
      catch (err) { document.getElementById("eventsBody").innerHTML = `<tr><td colspan="9">History unavailable; not an empty result.</td></tr>`; throw err; }
      if (version !== refreshVersion) return;
      renderEvents(events.items || []);
      setStatus(`Loaded ${events.items?.length || 0} matching events from ${historySource()}.`, "ok");
    }
    async function downloadExport(path, filename){
      const res = await fetch(path, { credentials:"same-origin", headers: authHeaders("GET") });
      if(!res.ok) { let body = {}; try { body = JSON.parse(await res.text()); } catch { body = {}; } throw failure(res, body); }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = filename; a.click();
      URL.revokeObjectURL(url);
    }
    document.getElementById("saveBtn").addEventListener("click", async () => {
      try {
      await api("/platform/admin-mode");
      sessionStorage.setItem("pqc_platform_admin_key", keyInput.value.trim());
      sessionStorage.setItem("pqc_platform_admin_role", roleInput.value || "owner");
      setStatus("Credential remembered for this tab. Sign out to remove it.", "ok");
      } catch (err) { setStatus(err.message, "bad"); }
    });
    document.getElementById("signOutBtn").addEventListener("click", async () => {
      if (liveTimer) clearInterval(liveTimer);
      if (sessionAuth.active) {
        // End the server-side session too, then return to the console sign-in.
        try { await fetch("/platform/session/logout", { method:"POST", headers:{ "x-csrf-token": sessionAuth.csrf }, credentials:"same-origin" }); } catch { /* the cookie expires on its own */ }
        location.replace("/vendor-admin/");
        return;
      }
      for (const storage of [sessionStorage, localStorage]) ["pqc_platform_admin_key", "pqc_platform_key", "pqc_platform_admin_role"].forEach(name => storage.removeItem(name));
      location.reload();
    });
    ["ipFilter", "pathFilter"].forEach(id => document.getElementById(id).addEventListener("keydown", event => {
      if (event.key === "Enter") { event.preventDefault(); loadEvents().catch(err => setStatus(err.message, "bad")); }
    }));
    document.getElementById("refreshBtn").addEventListener("click", () => loadTraffic().catch(err => setStatus(err.message, "bad")));
    document.getElementById("eventsBtn").addEventListener("click", () => loadEvents().catch(err => setStatus(err.message, "bad")));
    document.getElementById("historySource").addEventListener("change", () => loadEvents().catch(err => setStatus(err.message, "bad")));
    document.getElementById("exportNdjsonBtn").addEventListener("click", () => downloadExport(`/platform/traffic/export.ndjson?limit=5000&${filterQuery()}`, "pqc-traffic-events.ndjson").catch(err => setStatus(err.message, "bad")));
    document.getElementById("exportOtelBtn").addEventListener("click", () => downloadExport(`/platform/traffic/otel?limit=5000&${filterQuery()}`, "pqc-traffic-otel.json").catch(err => setStatus(err.message, "bad")));
    document.getElementById("clearTrafficBtn").addEventListener("click", async () => {
      if(!confirm("Clear the in-memory traffic buffer?")) return;
      try{
        await api("/platform/traffic/clear", { method:"POST" });
        await loadTraffic();
      }catch(err){ setStatus(err.message, "bad"); }
    });
    liveBtn.addEventListener("click", () => {
      if(liveTimer){
        clearInterval(liveTimer); liveTimer = null; liveBtn.textContent = "Live Off"; return;
      }
      if (!keyInput.value.trim() && !sessionAuth.active) { setStatus("Enter a platform key before enabling refresh.", "bad"); return; }
      liveTimer = setInterval(() => { if (!document.hidden) loadTraffic().catch(err => setStatus(err.message, "bad")); }, 5000);
      liveBtn.textContent = "Live On";
      loadTraffic().catch(err => setStatus(err.message, "bad"));
    });
    document.addEventListener("visibilitychange", () => {
      if (liveTimer) liveBtn.textContent = document.hidden ? "Live paused" : "Live On";
    });
    window.addEventListener("pagehide", () => { if (liveTimer) clearInterval(liveTimer); });
    loadPolicy();
    // Shared client for admin-shell.js (notifications bell) so it follows the same credential.
    window.TrafficLens = { api, connected: () => sessionAuth.active || !!keyInput.value.trim(), session: () => sessionAuth.active };
    detectSession().then(active => { if (active) loadTraffic().catch(err => setStatus(err.message, "bad")); });
