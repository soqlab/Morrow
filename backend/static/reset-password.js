(() => {
  "use strict";
  /* Password reset page (/reset-password, and /reset-password#token=... from the email).

     Without a token it asks for an email address (POST /auth/password-reset/request), whose answer is
     the same whether or not the address has an account. With a token it asks for the new password
     (POST /auth/password-reset/confirm). Accounts that sign in with passkeys, and every account on a
     passkeys-only server, are emailed /reset-password#recover=... instead: account recovery, which
     registers a new passkey (POST /auth/passkey/register/begin and /finish, kind "recover", through
     /ui/passkey.js) and can remove the others. The token arrives in the URL fragment, which never
     reaches a server log or a Referer header; it is kept in sessionStorage for this tab and removed
     from the address bar. No third-party requests.

     Without email: "I have a recovery code" trades one recovery code (POST /auth/recovery-codes/redeem)
     for the same kind of short-lived recovery ticket, then runs the same passkey ceremony. And
     /reset-password#setup=... is the single-use link an administrator hands to someone whose account
     they created (possibly without an email): it creates the account's first passkey (kind "setup"). */

  const TOKEN_KEY = "pq_reset_token";
  const RECOVER_KEY = "pq_recover_token";
  const SETUP_KEY = "pq_setup_token";
  const $ = id => document.getElementById(id);
  const esc = value => String(value ?? "").replace(/[&<>"']/g, ch => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[ch]));
  const store = {
    get: key => { try { return sessionStorage.getItem(key) || ""; } catch { return ""; } },
    set: (key, value) => { try { sessionStorage.setItem(key, value); } catch { /* storage blocked: works for this load */ } },
    del: key => { try { sessionStorage.removeItem(key); } catch { /* ignore */ } }
  };

  function readToken(name, key) {
    const match = new RegExp(`(?:^|[#&])${name}=([A-Za-z0-9_\\-]{16,256})(?:&|$)`).exec(location.hash || "");
    if (match) {
      store.set(key, match[1]);
      try { history.replaceState(null, "", location.pathname + location.search); } catch { /* ignore */ }
      return match[1];
    }
    return store.get(key);
  }
  const setupToken = readToken("setup", SETUP_KEY);
  let recoverToken = setupToken ? "" : readToken("recover", RECOVER_KEY);
  const token = setupToken || recoverToken ? "" : readToken("token", TOKEN_KEY);

  let passkeysOnly = false;
  let codesEnabled = false;
  let mailEnabled = true;
  async function loadConfig() {
    try {
      const res = await fetch("/auth/config", { cache: "no-store", credentials: "same-origin" });
      const cfg = res.ok ? await res.json() : {};
      passkeysOnly = !!(cfg && cfg.passkeys_only);
      codesEnabled = !!(cfg && cfg.recovery_codes_enabled);
      mailEnabled = !cfg || cfg.password_reset_enabled !== false;
    } catch { passkeysOnly = false; }
  }

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
    if (passkeysOnly) {
      $("resetTitle").textContent = "Recover your account.";
    }
    if (!mailEnabled && codesEnabled) return askCode();
    state({ title: passkeysOnly ? "Recover your account." : "Reset your password or recover your account.",
      lead: passkeysOnly ? "Lost your passkey? Enter your account's email address and we'll email you a link to create a new one, if your account allows recovery by email."
        : "Enter your account's email address. We'll email you a link to choose a new password, or to create a new passkey if you sign in with one, if your account allows recovery by email.",
      body: `<form class="invite-form" novalidate>
          <label>Email<input id="resetEmail" type="email" autocomplete="username" required maxlength="320"></label>
          <p class="invite-error" id="resetError" role="alert"></p>
        </form>`,
      actions: [{ label: passkeysOnly ? "Email me a recovery link" : "Email me a link", primary: true, run: sendLink },
        ...(codesEnabled ? [{ label: "I have a recovery code", run: askCode }] : []), { label: "Back to sign in", href: "/ui/" }] });
    $("resetEmail").focus();
  }

  // ---------- a recovery code instead of email ----------
  function askCode() {
    const supported = window.MorrowPasskey && MorrowPasskey.supported();
    state({ title: "Use a recovery code.", lead: "Enter one of the recovery codes you saved. You'll create a new passkey, and you'll be signed out everywhere else. Each code works once.",
      body: `<form class="invite-form" novalidate>
          <label>Recovery code<input id="resetCode" autocomplete="off" autocapitalize="characters" spellcheck="false" maxlength="40" placeholder="XXXX-XXXX-XXXX-XXXX"></label>
          <label class="invite-check" style="display:flex;gap:10px;align-items:center;text-transform:none;letter-spacing:0;font-size:14px">
            <input id="recoverRevoke" type="checkbox" style="width:auto"> Also remove my other passkeys (a lost or stolen device)</label>
          <p class="invite-error" id="resetError" role="alert">${supported ? "" : "This browser can't create a passkey. Open this page in a current browser, or on your phone."}</p>
        </form>`,
      actions: [{ label: "Use code and create a passkey", primary: true, run: useCode },
        ...(mailEnabled ? [{ label: "Use email instead", run: askEmail }] : []), { label: "Back to sign in", href: "/ui/" }] });
    $("resetCode").focus();
  }
  async function useCode() {
    const error = $("resetError");
    if (!window.MorrowPasskey || !MorrowPasskey.supported()) { error.textContent = "This browser can't create a passkey."; return; }
    const code = $("resetCode").value.trim();
    if (!code) { error.textContent = "Enter one of your recovery codes."; return; }
    if (!recoverToken) {
      const r = await request("/auth/recovery-codes/redeem", { code });
      if (!r.ok || !r.data) {
        if (r.status === 429) { error.textContent = "Too many attempts. Wait a minute, then try again."; return; }
        error.textContent = detail(r) || (r.status === 0 ? "We couldn't reach the server. Try again." : `The server answered ${r.status}.`);
        return;
      }
      // Kept for this tab only: if creating the passkey fails, pressing the button again reuses it.
      recoverToken = r.data.recovery_token;
      store.set(RECOVER_KEY, recoverToken);
    }
    await recover();
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

  // ---------- with a recovery link: create a new passkey ----------
  function askPasskey() {
    const supported = window.MorrowPasskey && MorrowPasskey.supported();
    state({ title: "Create a new passkey.", lead: "This replaces the way you sign in. It signs you out on every other device.",
      body: `<form class="invite-form" novalidate>
          <label class="invite-check" style="display:flex;gap:10px;align-items:center;text-transform:none;letter-spacing:0;font-size:14px">
            <input id="recoverRevoke" type="checkbox" style="width:auto"> Also remove my other passkeys (a lost or stolen device)</label>
          <p class="invite-error" id="resetError" role="alert">${supported ? "" : "This browser can't create a passkey. Open the link in a current browser, or on your phone."}</p>
        </form>`,
      actions: [{ label: "Create passkey", primary: true, run: recover }] });
  }
  function linkUnusable(r) {
    store.del(RECOVER_KEY);
    recoverToken = "";
    return state({ title: "This link can't be used.", lead: detail(r) || "It may have expired or already been used.", tone: "bad",
      actions: [{ label: "Request a new link", primary: true, run: askEmail }] });
  }
  async function recover() {
    const error = $("resetError");
    if (!window.MorrowPasskey || !MorrowPasskey.supported()) { error.textContent = "This browser can't create a passkey."; return; }
    error.textContent = "";
    const begin = await request("/auth/passkey/register/begin", { kind: "recover", token: recoverToken });
    if (!begin.ok || !begin.data) {
      if (begin.status === 404 || begin.status === 410) return linkUnusable(begin);
      error.textContent = detail(begin) || (begin.status === 0 ? "We couldn't reach the server. Try again." : `The server answered ${begin.status}.`);
      return;
    }
    let credential;
    try { credential = await MorrowPasskey.create(begin.data.options); }
    catch (e) { error.textContent = MorrowPasskey.message(e) || "No passkey was created. Press the button to try again."; return; }
    const r = await request("/auth/passkey/register/finish", { challenge_id: begin.data.challenge_id, credential, token: recoverToken,
      revoke_other_passkeys: !!$("recoverRevoke").checked });
    if (r.ok && r.data && r.data.access_token) {
      store.del(RECOVER_KEY);
      recoverToken = "";
      try {
        localStorage.setItem("morrow_token", r.data.access_token);
        if (r.data.refresh_token) localStorage.setItem("morrow_refresh", r.data.refresh_token);
      } catch { /* storage blocked: sign in with the new passkey */ }
      return state({ title: "You're back in.", lead: r.data.other_passkeys_removed ? "Your other passkeys were removed." : "Your new passkey is ready.", tone: "ok",
        actions: [{ label: "Open the console", primary: true, href: "/ui/" }] });
    }
    if (r.status === 404 || r.status === 410) return linkUnusable(r);
    if (r.status === 429) { error.textContent = "Too many attempts. Wait a minute, then try again."; return; }
    error.textContent = detail(r) || (r.status === 0 ? "We couldn't reach the server. Try again." : `The server answered ${r.status}.`);
  }

  // ---------- with a setup link: the account's first passkey ----------
  function askSetup() {
    const supported = window.MorrowPasskey && MorrowPasskey.supported();
    state({ title: "Set up your account.", lead: "Create a passkey to sign in to Morrow. You'll use your fingerprint, face, device PIN or a security key; there is no password.",
      body: `<form class="invite-form" novalidate>
          <p class="invite-error" id="resetError" role="alert">${supported ? "" : "This browser can't create a passkey. Open the link in a current browser, or on your phone."}</p>
        </form>`,
      actions: [{ label: "Create passkey", primary: true, run: setup }] });
  }
  async function setup() {
    const error = $("resetError");
    if (!window.MorrowPasskey || !MorrowPasskey.supported()) { error.textContent = "This browser can't create a passkey."; return; }
    error.textContent = "";
    const unusable = r => {
      store.del(SETUP_KEY);
      return state({ title: "This link can't be used.", lead: detail(r) || "It may have expired or already been used. Ask the person who set up your account for a new one.", tone: "bad",
        actions: [{ label: "Go to sign in", href: "/ui/" }] });
    };
    const begin = await request("/auth/passkey/register/begin", { kind: "setup", token: setupToken });
    if (!begin.ok || !begin.data) {
      if ([404, 409, 410].includes(begin.status)) return unusable(begin);
      error.textContent = detail(begin) || (begin.status === 0 ? "We couldn't reach the server. Try again." : `The server answered ${begin.status}.`);
      return;
    }
    let credential;
    try { credential = await MorrowPasskey.create(begin.data.options); }
    catch (e) { error.textContent = MorrowPasskey.message(e) || "No passkey was created. Press the button to try again."; return; }
    const r = await request("/auth/passkey/register/finish", { challenge_id: begin.data.challenge_id, credential, token: setupToken });
    if (r.ok && r.data && r.data.access_token) {
      store.del(SETUP_KEY);
      try {
        localStorage.setItem("morrow_token", r.data.access_token);
        if (r.data.refresh_token) localStorage.setItem("morrow_refresh", r.data.refresh_token);
      } catch { /* storage blocked: sign in with the new passkey */ }
      return state({ title: "You're in.", lead: "Your passkey is ready. Next, make recovery codes (under Sign-in & recovery in the console) so you can get back in if you lose it.", tone: "ok",
        actions: [{ label: "Open the console", primary: true, href: "/ui/" }] });
    }
    if ([404, 409, 410].includes(r.status)) return unusable(r);
    if (r.status === 429) { error.textContent = "Too many attempts. Wait a minute, then try again."; return; }
    error.textContent = detail(r) || (r.status === 0 ? "We couldn't reach the server. Try again." : `The server answered ${r.status}.`);
  }

  loadConfig().then(() => { setupToken ? askSetup() : recoverToken ? askPasskey() : token ? askPassword() : askEmail(); });
})();
