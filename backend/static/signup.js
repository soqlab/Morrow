(() => {
  "use strict";
  /* Public sign-up (/signup, /signup?watch=<domain>, /signup?claim=<domain>).

     Nothing to type but an optional name and organization name. One passkey ceremony
     (POST /auth/passkey/register/begin and /finish, kind "signup", through /ui/passkey.js) creates
     the organization, its admin account and the passkey, and answers with a session and ten recovery
     codes. The codes are shown here once and kept nowhere: not in storage, not in the address bar.
     Then, from a domain page: ?watch= starts watching that domain (PUT /instrument/watch/<domain>)
     and ?claim= starts its DNS claim (POST /instrument/claims/<domain>), and the visitor lands back on
     /<domain>. Without either, the console (/ui/). No email anywhere; no third-party requests. */

  const $ = id => document.getElementById(id);
  const esc = value => String(value ?? "").replace(/[&<>"']/g, ch => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[ch]));
  const store = {
    set: (key, value) => { try { localStorage.setItem(key, value); } catch { /* storage blocked */ } }
  };
  const DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/;
  const params = new URLSearchParams(location.search);
  const pick = name => {
    const value = String(params.get(name) || "").trim().toLowerCase().replace(/\.$/, "");
    return DOMAIN.test(value) ? value : "";
  };
  const watch = pick("watch");
  const claim = watch ? "" : pick("claim");
  let session = null;

  async function request(method, path, body, token) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 20000);
    const headers = { Accept: "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (token) headers.Authorization = "Bearer " + token;
    try {
      const res = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), signal: controller.signal,
        cache: "no-store", credentials: "same-origin", referrerPolicy: "no-referrer" });
      let data = null;
      try { data = await res.json(); } catch { data = null; }
      return { ok: res.ok, status: res.status, data };
    } catch {
      return { ok: false, status: 0, data: null };
    } finally { clearTimeout(timer); }
  }
  const detail = r => (r.data && typeof r.data.detail === "string" ? r.data.detail : "");
  const failure = r => detail(r) || (r.status === 0 ? "We couldn't reach the server. Try again." : `The server answered ${r.status}.`);

  function state({ title, lead, tone = "", body = "", actions = [] }) {
    $("signupTitle").textContent = title;
    $("signupLead").textContent = lead;
    const box = $("signupState");
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
  const signIn = { label: "Sign in", href: "/ui/" };

  // ---------- the form ----------
  function ask() {
    const lead = watch ? `One passkey and you're watching ${watch}. No email, no password.`
      : claim ? `One passkey, then a DNS record proves ${claim} is yours. No email, no password.`
      : "One passkey on this device, and you're in. No email, no password.";
    state({ title: watch ? `Watch ${watch}.` : claim ? `Claim ${claim}.` : "Create your account.", lead,
      body: `<form class="invite-form" novalidate>
          <label>Your name (optional)<input id="signupName" type="text" autocomplete="name" maxlength="120"></label>
          <label>Organization (optional)<input id="signupOrg" type="text" autocomplete="organization" maxlength="120"></label>
          <div class="signup-trap" aria-hidden="true"><label>Website<input id="signupWebsite" type="text" tabindex="-1" autocomplete="off"></label></div>
          <p class="invite-error" id="signupError" role="alert"></p>
        </form>`,
      actions: [{ label: "Create passkey and account", primary: true, run: create }, signIn] });
    $("signupName").focus();
  }

  async function create() {
    const error = $("signupError");
    error.textContent = "";
    const begin = await request("POST", "/auth/passkey/register/begin", { kind: "signup", full_name: $("signupName").value.trim(),
      organization: $("signupOrg").value.trim(), website: $("signupWebsite").value });
    if (!begin.ok || !begin.data) {
      if (begin.status === 404) return closed(detail(begin));
      error.textContent = begin.status === 429 && !detail(begin) ? "Too many attempts. Wait a minute, then try again." : failure(begin);
      return;
    }
    let credential;
    try { credential = await MorrowPasskey.create(begin.data.options); }
    catch (e) { error.textContent = MorrowPasskey.message(e) || "No passkey was created. Press the button to try again."; return; }
    const r = await request("POST", "/auth/passkey/register/finish", { challenge_id: begin.data.challenge_id, credential });
    if (!r.ok || !r.data || !r.data.access_token) {
      error.textContent = r.status === 429 && !detail(r) ? "Too many attempts. Wait a minute, then try again." : failure(r);
      return;
    }
    session = r.data;
    store.set("morrow_token", session.access_token);
    if (session.refresh_token) store.set("morrow_refresh", session.refresh_token);
    showCodes(session.recovery_codes || []);
  }

  // ---------- the recovery codes, once ----------
  function showCodes(codes) {
    const org = session && session.organization ? session.organization.name : "";
    state({ title: "Save your recovery codes.", tone: "ok",
      lead: `Your account${org ? ` and ${org}` : ""} are ready. These codes are shown once. Each one gets you back in once if you lose your passkey.`,
      body: `<ol class="signup-codes" id="signupCodes">${codes.map(code => `<li>${esc(code)}</li>`).join("")}</ol>
        ${para("Keep them somewhere safe and separate from this device: a password manager, or on paper. Morrow can't show them again, and it never emails you.")}
        <label class="signup-check"><input id="signupSaved" type="checkbox"> I've saved my recovery codes</label>
        <p class="invite-error" id="signupError" role="alert"></p>`,
      actions: [{ label: watch ? `Continue to ${watch}` : claim ? `Continue to ${claim}` : "Open Morrow", primary: true, run: next },
        { label: "Download codes", run: () => download(codes) }, { label: "Copy codes", run: button => copy(codes, button) }] });
  }
  function codesText(codes) {
    return `Morrow recovery codes\n${location.origin}\n\n${codes.join("\n")}\n\nEach code works once. Use one under "Lost your passkey?" on the sign-in screen.\n`;
  }
  function download(codes) {
    const blob = new Blob([codesText(codes)], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "morrow-recovery-codes.txt";
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 0);
  }
  async function copy(codes, button) {
    try { await navigator.clipboard.writeText(codesText(codes)); button.textContent = "Copied"; }
    catch { $("signupError").textContent = "Copying didn't work here. Select the codes and copy them, or download them."; }
  }

  // ---------- where to go next ----------
  async function next() {
    if (!$("signupSaved").checked) { $("signupError").textContent = "Tick the box once you've saved the codes. You can't see them again."; return; }
    const token = session && session.access_token;
    if (watch) {
      // If this fails the domain page says so and offers Watch again; the account is made either way.
      await request("PUT", `/instrument/watch/${encodeURIComponent(watch)}`, undefined, token);
      location.assign(`/${encodeURIComponent(watch)}`);
      return;
    }
    if (claim) {
      await request("POST", `/instrument/claims/${encodeURIComponent(claim)}`, undefined, token);
      location.assign(`/${encodeURIComponent(claim)}#w-claim`);
      return;
    }
    location.assign("/ui/");
  }

  function closed(text) {
    state({ title: "Sign-up isn't open here.", tone: "bad",
      lead: text || "This Morrow server doesn't take new accounts. Ask an admin of your organization for an invite link.",
      actions: [signIn] });
  }

  async function start() {
    let cfg = {};
    try {
      const res = await fetch("/auth/config", { cache: "no-store", credentials: "same-origin" });
      cfg = res.ok ? await res.json() : {};
    } catch { cfg = {}; }
    if (!cfg || !cfg.signup_enabled) return closed("");
    if (!window.MorrowPasskey || !MorrowPasskey.supported()) {
      return state({ title: "This browser can't create a passkey.", tone: "bad", lead: "Open this page in a current browser, or on your phone.",
        body: para("Passkeys need a recent Chrome, Edge, Safari or Firefox, and this site's own address over HTTPS."), actions: [signIn] });
    }
    ask();
  }
  start();
})();
