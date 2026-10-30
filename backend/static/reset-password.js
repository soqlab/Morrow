(() => {
  "use strict";
  /* Password reset page (/reset-password, and /reset-password#token=... from the email).

     Without a token it asks for an email address (POST /auth/password-reset/request), whose answer is
     the same whether or not the address has an account. With a token it asks for the new password
     (POST /auth/password-reset/confirm). The token arrives in the URL fragment, which never reaches a
     server log or a Referer header; it is kept in sessionStorage for this tab and removed from the
     address bar. No third-party requests. */

  const TOKEN_KEY = "pq_reset_token";
  const $ = id => document.getElementById(id);
  const esc = value => String(value ?? "").replace(/[&<>"']/g, ch => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[ch]));
  const store = {
    get: key => { try { return sessionStorage.getItem(key) || ""; } catch { return ""; } },
    set: (key, value) => { try { sessionStorage.setItem(key, value); } catch { /* storage blocked: works for this load */ } },
    del: key => { try { sessionStorage.removeItem(key); } catch { /* ignore */ } }
  };

  function readToken() {
    const match = /(?:^|[#&])token=([A-Za-z0-9_\-]{16,256})(?:&|$)/.exec(location.hash || "");
    if (match) {
      store.set(TOKEN_KEY, match[1]);
      try { history.replaceState(null, "", location.pathname + location.search); } catch { /* ignore */ }
      return match[1];
    }
    return store.get(TOKEN_KEY);
  }
  const token = readToken();

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
    $("resetTitle").textContent = title;
    $("resetLead").textContent = lead;
    const box = $("resetState");
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
    // The buttons sit outside the form, so Enter in a field presses the first one.
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

  // ---------- without a token: ask for the address ----------
  function askEmail() {
    state({ title: "Reset your password.", lead: "Enter the email address you sign in with. We'll email you a link to choose a new password.",
      body: `<form class="invite-form" novalidate>
          <label>Email<input id="resetEmail" type="email" autocomplete="username" required maxlength="320"></label>
          <p class="invite-error" id="resetError" role="alert"></p>
        </form>`,
      actions: [{ label: "Email me a reset link", primary: true, run: sendLink }, { label: "Back to sign in", href: "/ui/" }] });
    $("resetEmail").focus();
  }
  async function sendLink() {
    const email = $("resetEmail").value.trim();
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) { $("resetError").textContent = "Enter the email address you sign in with."; return; }
    const r = await request("/auth/password-reset/request", { email });
    if (r.ok) {
      return state({ title: "Check your email.", lead: detail(r) || "If an account exists for that address, we've emailed it a reset link.", tone: "ok",
        body: para("The link works once and expires after 30 minutes. Nothing arrived after a few minutes? Check your spam folder, or try again."),
        actions: [{ label: "Try again", run: askEmail }, { label: "Back to sign in", href: "/ui/" }] });
    }
    if (r.status === 429) { $("resetError").textContent = "Too many attempts. Wait a minute, then try again."; return; }
    if (r.status === 0) { $("resetError").textContent = "We couldn't reach the server. Try again."; return; }
    $("resetError").textContent = detail(r) || `The server answered ${r.status}.`;
  }

  // ---------- with a token: choose the new password ----------
  function askPassword() {
    state({ title: "Choose a new password.", lead: "This signs you out on every other device.",
      body: `<form class="invite-form" novalidate>
          <label>New password<input id="resetPassword" type="password" autocomplete="new-password" required minlength="10"></label>
          <label>Repeat new password<input id="resetPassword2" type="password" autocomplete="new-password" required minlength="10"></label>
          <p class="invite-error" id="resetError" role="alert"></p>
        </form>${para("At least 10 characters, including a digit.")}`,
      actions: [{ label: "Change password", primary: true, run: setPassword }] });
    $("resetPassword").focus();
  }
  async function setPassword() {
    const error = $("resetError");
    const password = $("resetPassword").value;
    if (password.length < 10 || !/[0-9]/.test(password)) { error.textContent = "Use at least 10 characters, including a digit."; return; }
    if (password !== $("resetPassword2").value) { error.textContent = "The two passwords don't match."; return; }
    error.textContent = "";
    const r = await request("/auth/password-reset/confirm", { token, password });
    if (r.ok) {
      store.del(TOKEN_KEY);
      try { localStorage.removeItem("morrow_token"); localStorage.removeItem("morrow_refresh"); } catch { /* ignore */ }
      return state({ title: "Password changed.", lead: "Sign in with your new password.", tone: "ok",
        actions: [{ label: "Sign in", primary: true, href: "/ui/" }] });
    }
    if (r.status === 404 || r.status === 410) {
      store.del(TOKEN_KEY);
      return state({ title: "This link can't be used.", lead: detail(r) || "It may have expired or already been used.", tone: "bad",
        actions: [{ label: "Request a new link", primary: true, run: askEmail }] });
    }
    if (r.status === 429) { error.textContent = "Too many attempts. Wait a minute, then try again."; return; }
    if (r.status === 0) { error.textContent = "We couldn't reach the server. Try again."; return; }
    error.textContent = detail(r) || `The server answered ${r.status}.`;
  }

  token ? askPassword() : askEmail();
})();
