(() => {
  "use strict";
  /* Invitation landing page (/invite#token=...).

     The token arrives in the URL fragment, which never reaches a server log or a Referer header.
     It is moved into sessionStorage for this tab and removed from the address bar. The page:
       1. previews the invitation (POST /auth/invite/preview, masked summary only);
       2. reads the console session from localStorage (pqc_token / pqc_refresh, the console's keys);
       3. offers sign-in through the console (returning here via sessionStorage), sign-out when the
          signed-in email does not match, and acceptance (POST /admin/accept-invite), which the
          server binds to the signed-in email and claims atomically.
     No third-party requests. */

  const TOKEN_KEY = "pqc_invite_token";
  const RETURN_KEY = "pqc_invite_return";
  const FLASH_KEY = "pqc_flash";
  const $ = id => document.getElementById(id);
  const esc = value => String(value ?? "").replace(/[&<>"']/g, ch => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[ch]));
  const store = {
    get: (area, key) => { try { return window[area].getItem(key) || ""; } catch { return ""; } },
    set: (area, key, value) => { try { window[area].setItem(key, value); } catch { /* storage blocked: the page still works for this load */ } },
    del: (area, key) => { try { window[area].removeItem(key); } catch { /* ignore */ } }
  };
  let preview = null;

  function readToken() {
    const match = /(?:^|[#&])token=([A-Za-z0-9_\-]{16,256})(?:&|$)/.exec(location.hash || "");
    if (match) {
      store.set("sessionStorage", TOKEN_KEY, match[1]);
      // Keep the code out of the visible address, history entries and screenshots.
      try { history.replaceState(null, "", location.pathname + location.search); } catch { /* ignore */ }
      return match[1];
    }
    return store.get("sessionStorage", TOKEN_KEY);
  }
  const token = readToken();

  async function request(path, { method = "GET", body, auth = false, timeout = 20000 } = {}) {
    const headers = {};
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const bearer = store.get("localStorage", "pqc_token");
    if (auth && bearer) headers.Authorization = "Bearer " + bearer;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    try {
      const res = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), signal: controller.signal, cache: "no-store", credentials: "same-origin", referrerPolicy: "no-referrer" });
      let data = null;
      try { data = await res.json(); } catch { data = null; }
      return { ok: res.ok, status: res.status, data };
    } catch {
      return { ok: false, status: 0, data: null };
    } finally { clearTimeout(timer); }
  }
  const detail = r => (r.data && typeof r.data.detail === "string" ? r.data.detail : "");

  // ---------- identity (the console's session) ----------
  function claims(jwt) {
    try {
      const part = String(jwt || "").split(".")[1];
      if (!part) return null;
      const json = decodeURIComponent(atob(part.replace(/-/g, "+").replace(/_/g, "/")).split("").map(c => "%" + c.charCodeAt(0).toString(16).padStart(2, "0")).join(""));
      return JSON.parse(json);
    } catch { return null; }
  }
  async function identity() {
    let jwt = store.get("localStorage", "pqc_token");
    let payload = claims(jwt);
    const expired = payload && payload.exp && payload.exp * 1000 < Date.now() + 5000;
    if ((!payload || expired) && store.get("localStorage", "pqc_refresh")) {
      const r = await request("/auth/refresh", { method: "POST", body: { refresh_token: store.get("localStorage", "pqc_refresh") } });
      if (r.ok && r.data && r.data.access_token) {
        store.set("localStorage", "pqc_token", r.data.access_token);
        jwt = r.data.access_token;
        payload = claims(jwt);
      } else if (r.status === 401) {
        store.del("localStorage", "pqc_token");
        return null;
      }
    }
    if (!payload || (payload.exp && payload.exp * 1000 < Date.now())) return null;
    const email = String(payload.email || (String(payload.sub || "").includes("@") ? payload.sub : "") || "").trim().toLowerCase();
    return { email, subject: String(payload.sub || "") };
  }
  const maskEmail = email => {
    const at = String(email || "").lastIndexOf("@");
    if (at < 0) return "";
    return `${email.slice(0, 1) || "*"}***@${email.slice(at + 1)}`;
  };

  // ---------- rendering ----------
  const STATUS_TEXT = { valid: "Valid", expired: "Expired", used: "Already used", revoked: "Revoked" };
  function summary(p) {
    const set = (id, value, fallback) => { const el = $(id); el.textContent = value || fallback; el.classList.remove("invite-skeleton"); };
    set("inviteOrg", p && p.organization_name, "Unknown");
    set("inviteRole", p && p.role, "Not shown");
    set("inviteEmail", p && p.invited_email_masked, "Not shown");
    let expires = "Not shown";
    if (p && p.expires_at) {
      const d = new Date(p.expires_at);
      expires = Number.isNaN(d.getTime()) ? p.expires_at : d.toLocaleString();
    }
    set("inviteExpires", expires, "Not shown");
    const pill = $("inviteStatus");
    pill.dataset.status = p ? p.status : "unknown";
    pill.textContent = p ? (STATUS_TEXT[p.status] || p.status) : "Unavailable";
  }
  function state({ title, lead, tone = "", body = "", actions = [] }) {
    $("inviteTitle").textContent = title;
    $("inviteLead").textContent = lead;
    const box = $("inviteState");
    box.dataset.tone = tone;
    box.innerHTML = `${body}${actions.length ? `<div class="invite-actions">${actions.map((a, i) => a.href
      ? `<a class="btn${a.primary ? " primary" : ""}" href="${esc(a.href)}">${esc(a.label)}</a>`
      : `<button class="btn${a.primary ? " primary" : ""}" type="button" data-action="${i}">${esc(a.label)}</button>`).join("")}</div>` : ""}`;
    box.querySelectorAll("[data-action]").forEach(button => {
      const action = actions[Number(button.dataset.action)];
      button.addEventListener("click", async () => {
        button.disabled = true;
        try { await action.run(button); } finally { if (button.isConnected) button.disabled = false; }
      });
    });
  }
  const para = text => `<p>${esc(text)}</p>`;
  const noToken = () => {
    summary(null);
    state({ title: "This link has no invitation code.", lead: "Open the full link from your invitation message.", tone: "bad",
      body: para("Invitation links end with #token= and a long code. If the link was split across lines in your email, copy the whole thing into the address bar."),
      actions: [{ label: "Open console", href: "/ui/" }] });
  };

  async function load() {
    if (!token) return noToken();
    const r = await request("/auth/invite/preview", { method: "POST", body: { token } });
    if (r.status === 0) {
      summary(null);
      return state({ title: "We couldn't reach the server.", lead: "Check your connection and try again.", tone: "bad",
        body: para("Your invitation has not been changed."), actions: [{ label: "Try again", primary: true, run: load }] });
    }
    if (r.status === 429) {
      summary(null);
      return state({ title: "Too many attempts.", lead: "Wait a minute, then try again.", tone: "bad",
        body: para("Invitation lookups are rate limited to protect invitation codes."), actions: [{ label: "Try again", primary: true, run: load }] });
    }
    if (r.status === 404 || r.status === 422) {
      summary(null);
      return state({ title: "We couldn't find this invitation.", lead: "The link may be incomplete or mistyped.", tone: "bad",
        body: para("Copy the whole link from your invitation message. If it still fails, ask the person who invited you to send a new invitation."),
        actions: [{ label: "Open console", href: "/ui/" }] });
    }
    if (!r.ok || !r.data) {
      summary(null);
      return state({ title: "The invitation could not be checked.", lead: detail(r) || `The server answered ${r.status}.`, tone: "bad",
        actions: [{ label: "Try again", primary: true, run: load }] });
    }
    preview = r.data;
    summary(preview);
    return render();
  }

  async function render() {
    const p = preview;
    if (p.status === "expired") {
      return state({ title: "This invitation has expired.", lead: `It was for ${p.organization_name}.`, tone: "bad",
        body: para("Invitations expire for your safety. Ask your administrator to send a new one."), actions: [{ label: "Open console", href: "/ui/" }] });
    }
    if (p.status === "used") {
      return state({ title: "This invitation has already been used.", lead: `An invitation works once. It was for ${p.organization_name}.`, tone: "bad",
        body: para("If you accepted it yourself, just sign in to the console. Otherwise, ask your administrator for a new invitation."),
        actions: [{ label: "Open console", primary: true, href: "/ui/" }] });
    }
    if (p.status === "revoked") {
      return state({ title: "This invitation was revoked.", lead: `An administrator withdrew it${p.organization_name ? ` for ${p.organization_name}` : ""}.`, tone: "bad",
        body: para("Ask your administrator if you still need access."), actions: [{ label: "Open console", href: "/ui/" }] });
    }
    const who = await identity();
    if (!who) {
      return state({ title: `Join ${p.organization_name}.`, lead: `You're invited as ${p.role || "a member"}. Sign in with ${p.invited_email_masked || "the invited address"} to accept.`,
        body: para("Signing in opens the console and brings you back here. This server doesn't offer self sign-up: if you don't have an account for the invited address yet, ask the person who invited you to create one."),
        actions: [{ label: "Sign in to accept", primary: true, run: signIn }] });
    }
    if (!who.email || (p.invited_email_masked && maskEmail(who.email) !== p.invited_email_masked)) {
      return state({ title: "You're signed in with a different email.", lead: `This invitation is for ${p.invited_email_masked}.`, tone: "bad",
        body: para(`You're signed in as ${who.email || "an account without an email address"}. Sign out, then sign in with the invited address to accept.`),
        actions: [{ label: "Sign out", primary: true, run: signOut }] });
    }
    return state({ title: `Join ${p.organization_name}.`, lead: `You're signed in as ${who.email}. Accept to join as ${p.role || "a member"}.`,
      actions: [{ label: "Accept invitation", primary: true, run: accept }, { label: "Sign out", run: signOut }] });
  }

  function signIn() {
    store.set("sessionStorage", RETURN_KEY, JSON.stringify({ path: `/invite#token=${token}`, at: Date.now() }));
    location.assign("/ui/?signin=invite");
  }
  async function signOut() {
    const refresh = store.get("localStorage", "pqc_refresh");
    if (refresh) await request("/auth/logout", { method: "POST", body: { refresh_token: refresh } });
    store.del("localStorage", "pqc_token");
    store.del("localStorage", "pqc_refresh");
    await render();
  }
  async function accept() {
    const r = await request("/admin/accept-invite", { method: "POST", auth: true, body: { token } });
    if (r.ok) {
      store.del("sessionStorage", TOKEN_KEY);
      store.del("sessionStorage", RETURN_KEY);
      store.set("sessionStorage", FLASH_KEY, JSON.stringify({ title: "Invitation accepted", message: `You joined ${preview.organization_name}.`, kind: "ok" }));
      state({ title: "Invitation accepted.", lead: "Opening the console.", tone: "ok" });
      location.assign("/ui/");
      return;
    }
    if (r.status === 0) {
      return state({ title: "We couldn't reach the server.", lead: "Your invitation was not accepted yet.", tone: "bad",
        actions: [{ label: "Try again", primary: true, run: accept }] });
    }
    if (r.status === 401) {
      store.del("localStorage", "pqc_token");
      return state({ title: "Your session has ended.", lead: "Sign in again to accept.", tone: "bad", actions: [{ label: "Sign in to accept", primary: true, run: signIn }] });
    }
    if (r.status === 403) {
      return state({ title: "You're signed in with a different email.", lead: detail(r) || `This invitation is for ${preview.invited_email_masked}.`, tone: "bad",
        actions: [{ label: "Sign out", primary: true, run: signOut }] });
    }
    if (r.status === 409) { preview.status = "used"; summary(preview); return render(); }
    if (r.status === 410) { preview.status = "expired"; summary(preview); return render(); }
    if (r.status === 404) { preview.status = "revoked"; summary(preview); return render(); }
    if (r.status === 429) {
      return state({ title: "Too many attempts.", lead: "Wait a minute, then try again.", tone: "bad", actions: [{ label: "Try again", primary: true, run: accept }] });
    }
    return state({ title: "The invitation was not accepted.", lead: detail(r) || `The server answered ${r.status}.`, tone: "bad",
      actions: [{ label: "Try again", primary: true, run: accept }] });
  }

  load();
})();
