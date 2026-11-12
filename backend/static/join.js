(() => {
  "use strict";
  /* Domain team sign-in (/join, and /join#token=... from the email).

     Without a token: ask for the work email (POST /auth/team-join/request; the answer is the same
     whether or not the domain admits new members). With a token: show the organization
     (POST /auth/team-join/preview), then create a passkey (POST /auth/passkey/register/begin and
     /finish with kind "join"), which creates the account, joins it to the organization and signs in.
     The token arrives in the URL fragment, which never reaches a server log or a Referer header; it
     is kept in sessionStorage for this tab and removed from the address bar. No third-party requests. */

  const TOKEN_KEY = "pq_join_token";
  const FLASH_KEY = "pq_flash";
  const $ = id => document.getElementById(id);
  const esc = value => String(value ?? "").replace(/[&<>"']/g, ch => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[ch]));
  const store = {
    get: (area, key) => { try { return window[area].getItem(key) || ""; } catch { return ""; } },
    set: (area, key, value) => { try { window[area].setItem(key, value); } catch { /* storage blocked */ } },
    del: (area, key) => { try { window[area].removeItem(key); } catch { /* ignore */ } }
  };

  function readToken() {
    const match = /(?:^|[#&])token=([A-Za-z0-9_\-]{16,256})(?:&|$)/.exec(location.hash || "");
    if (match) {
      store.set("sessionStorage", TOKEN_KEY, match[1]);
      try { history.replaceState(null, "", location.pathname + location.search); } catch { /* ignore */ }
      return match[1];
    }
    return store.get("sessionStorage", TOKEN_KEY);
  }
  const token = readToken();
  let preview = null;

  async function request(path, body) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 20000);
    try {
      const res = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body), signal: controller.signal, cache: "no-store", credentials: "same-origin", referrerPolicy: "no-referrer" });
      let data = null;
      try { data = await res.json(); } catch { data = null; }
      return { ok: res.ok, status: res.status, data };
    } catch {
      return { ok: false, status: 0, data: null };
    } finally { clearTimeout(timer); }
  }
  const detail = r => (r.data && typeof r.data.detail === "string" ? r.data.detail : "");

  function state({ title, lead, tone = "", body = "", actions = [] }) {
    $("joinTitle").textContent = title;
    $("joinLead").textContent = lead;
    const box = $("joinState");
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
    const form = box.querySelector("form");
    if (form) {
      form.addEventListener("submit", event => event.preventDefault());
      form.addEventListener("keydown", event => {
        if (event.key !== "Enter") return;
        event.preventDefault();
        const first = box.querySelector('[data-action="0"]');
        if (first && !first.disabled) first.click();
      });
    }
  }
  const para = text => `<p>${esc(text)}</p>`;

  // ---------- without a token: ask for the work address ----------
  function askEmail() {
    $("joinMeta").hidden = true;
    state({ title: "Join your team.", lead: "Enter your work email address. If your organization lets people with that address join, we'll email you a link.",
      body: `<form class="invite-form" novalidate>
          <label>Work email<input id="joinEmailInput" type="email" autocomplete="email" required maxlength="320"></label>
          <p class="invite-error" id="joinError" role="alert"></p>
        </form>`,
      actions: [{ label: "Email me a link", primary: true, run: sendLink }, { label: "Sign in instead", href: "/ui/" }] });
    $("joinEmailInput").focus();
  }
  async function sendLink() {
    const email = $("joinEmailInput").value.trim();
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) { $("joinError").textContent = "Enter your work email address."; return; }
    const r = await request("/auth/team-join/request", { email });
    if (r.ok) {
      return state({ title: "Check your email.", lead: detail(r) || "If your organization lets people with this address join, we've emailed you a link.", tone: "ok",
        body: para("The link works once and expires after 30 minutes. Nothing arrived? Your organization may not use team sign-in: ask your administrator for an invitation."),
        actions: [{ label: "Try another address", run: askEmail }, { label: "Back to sign in", href: "/ui/" }] });
    }
    if (r.status === 429) { $("joinError").textContent = "Too many attempts. Wait a minute, then try again."; return; }
    if (r.status === 0) { $("joinError").textContent = "We couldn't reach the server. Try again."; return; }
    $("joinError").textContent = detail(r) || `The server answered ${r.status}.`;
  }

  // ---------- with a token: create the passkey and join ----------
  function badLink(r) {
    store.del("sessionStorage", TOKEN_KEY);
    $("joinMeta").hidden = true;
    return state({ title: "This link can't be used.", lead: detail(r) || "It may have expired or already been used.", tone: "bad",
      actions: [{ label: "Request a new link", primary: true, run: askEmail }, { label: "Sign in", href: "/ui/" }] });
  }
  async function load() {
    const r = await request("/auth/team-join/preview", { token });
    if (r.status === 0) {
      return state({ title: "We couldn't reach the server.", lead: "Check your connection and try again.", tone: "bad", actions: [{ label: "Try again", primary: true, run: load }] });
    }
    if (!r.ok || !r.data) return badLink(r);
    preview = r.data;
    $("joinMeta").hidden = false;
    for (const [id, value] of [["joinOrg", preview.organization_name], ["joinEmail", preview.email_masked], ["joinRole", "Viewer"]]) {
      const el = $(id); el.textContent = value || ""; el.classList.remove("invite-skeleton");
    }
    if (!window.MorrowPasskey || !MorrowPasskey.supported()) {
      return state({ title: "This browser can't create a passkey.", lead: "Open the link on a device with a current browser.", tone: "bad",
        body: para("Passkeys need a recent Chrome, Edge, Safari or Firefox, and this site's own address over HTTPS.") });
    }
    state({ title: `Join ${preview.organization_name}.`, lead: `Create a passkey for ${preview.email_masked} on this device. You'll use it to sign in; there is no password.`,
      body: `<form class="invite-form" novalidate>
          <label>Your name (optional)<input id="joinName" type="text" autocomplete="name" maxlength="200"></label>
          <p class="invite-error" id="joinError" role="alert"></p>
        </form>`,
      actions: [{ label: "Create passkey and join", primary: true, run: join }] });
  }
  async function join() {
    const error = $("joinError");
    error.textContent = "";
    const begin = await request("/auth/passkey/register/begin", { kind: "join", token, full_name: $("joinName").value.trim() });
    if (!begin.ok) {
      if (begin.status === 404 || begin.status === 410) return badLink(begin);
      if (begin.status === 409) {
        return state({ title: "You already have an account.", lead: "Sign in with your passkey instead.", tone: "bad", actions: [{ label: "Sign in", primary: true, href: "/ui/" }] });
      }
      error.textContent = detail(begin) || (begin.status === 0 ? "We couldn't reach the server. Try again." : `The server answered ${begin.status}.`);
      return;
    }
    let credential;
    try { credential = await MorrowPasskey.create(begin.data.options); }
    catch (e) { error.textContent = MorrowPasskey.message(e) || "No passkey was created. Press the button to try again."; return; }
    const r = await request("/auth/passkey/register/finish", { challenge_id: begin.data.challenge_id, credential, token });
    if (r.ok && r.data && r.data.access_token) {
      store.set("localStorage", "morrow_token", r.data.access_token);
      if (r.data.refresh_token) store.set("localStorage", "morrow_refresh", r.data.refresh_token);
      store.del("sessionStorage", TOKEN_KEY);
      store.set("sessionStorage", FLASH_KEY, JSON.stringify({ title: "Welcome to Morrow", message: `You joined ${preview.organization_name}.`, kind: "ok" }));
      state({ title: "You're in.", lead: "Opening the console.", tone: "ok" });
      location.assign("/ui/");
      return;
    }
    if (r.status === 404 || r.status === 410) return badLink(r);
    if (r.status === 429) { error.textContent = "Too many attempts. Wait a minute, then try again."; return; }
    error.textContent = detail(r) || (r.status === 0 ? "We couldn't reach the server. Try again." : `The server answered ${r.status}.`);
  }

  token ? load() : askEmail();
})();
