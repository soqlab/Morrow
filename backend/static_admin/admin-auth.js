// Operator sign-in for the vendor admin console: SSO button, the MFA challenge and enrolment steps,
// step-up prompts for destructive actions, the operator-menu auth summary, MFA management on the
// Operators page, and console sessions on the Sessions page. Server side: services/operator_auth.py.
//
// SSO uses an HttpOnly session cookie. This script never sees it and stores nothing: the CSRF token
// comes from /platform/whoami and lives in memory (index.js sessionAuth).
(() => {
  "use strict";
  const $ = id => document.getElementById(id);
  const A = () => window.AirlockAdmin;
  const esc = value => String(value ?? "").replace(/[&<>"']/g, ch => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[ch]));
  const METHOD_LABEL = { sso: "SSO", operator_key: "Named operator key", shared_key: "Shared platform key", break_glass: "Break-glass shared key" };
  const SSO_ERRORS = {
    sso_not_configured: "SSO is not configured for this console. Use an operator key.",
    sso_unavailable: "The identity provider could not be reached. Try again, or use an operator key.",
    sso_idp_error: "The identity provider cancelled or refused the sign-in.",
    sso_state_mismatch: "That sign-in response did not start in this browser. Start again.",
    sso_state_unknown: "That sign-in link was already used. Start again.",
    sso_state_expired: "The sign-in took too long. Start again.",
    sso_token_exchange_failed: "The identity provider refused the sign-in code. Start again.",
    sso_token_expired: "The identity token expired. Check this computer's clock and start again.",
    sso_token_audience: "The identity provider issued a token for a different application. Ask an administrator to check the client ID.",
    sso_token_issuer: "The identity token came from an unexpected provider.",
    sso_nonce_mismatch: "The identity token did not match this sign-in. Start again.",
    sso_email_unverified: "Your identity provider has not verified your email address.",
    sso_email_missing: "Your identity provider did not share an email address.",
    sso_operator_unknown: "Your account is not an authorized platform operator. Ask an owner to add you to the operator roster.",
  };
  let config = null;
  let who = null;
  let flow = null; // { mode: "verify" | "enrol" | "codes", recovery: bool }

  const csrfCookie = () => document.cookie.split("; ").some(c => c.startsWith("morrow_admin_csrf="));
  const codeOf = data => (data && data.detail && typeof data.detail === "object" && data.detail.code) || "";
  const messageOf = (data, res) => {
    const d = data && data.detail;
    if (d && typeof d === "object") return d.message || d.code || `${res.status}`;
    return d || `${res.status} ${res.statusText}`;
  };
  async function call(path, { method = "GET", json, csrf = "" } = {}) {
    const headers = {};
    if (csrf) headers["x-csrf-token"] = csrf;
    if (json !== undefined) headers["Content-Type"] = "application/json";
    const res = await fetch(path, { method, headers, body: json === undefined ? undefined : JSON.stringify(json), cache: "no-store", credentials: "same-origin" });
    let data = {};
    try { data = await res.json(); } catch { data = {}; }
    return { res, data };
  }
  function showError(message) { const el = $("authError"); if (!el) return; el.textContent = message || ""; el.hidden = !message; }
  const fmtTime = value => (A() ? A().fmtTime(value) : String(value || "—"));

  // ── Sign-in screen ──────────────────────────────────────────────────────────
  async function boot() {
    const params = new URLSearchParams(location.search);
    const error = params.get("sso_error");
    if (error) {
      showError(SSO_ERRORS[error] || "Sign-in failed. Start again.");
      history.replaceState(null, "", location.pathname + location.hash);
    }
    try {
      const { res, data } = await call("/platform/auth-config");
      config = res.ok ? data : null;
    } catch { config = null; }
    if (config?.sso_enabled) {
      $("ssoSlot").hidden = false;
      $("keyDisclosure").open = false;
      $("keyDisclosure").classList.add("secondary");
    }
    if (config && !config.break_glass_allowed) {
      $("keyDisclosureSummary").textContent = "Use a named operator key";
      $("roleBindingNote").textContent = `The shared platform key is disabled in ${config.environment}; named operator keys still work${config.mfa_required ? " with MFA" : ""}.`;
    }
    // Only a browser that has signed in with SSO carries the readable CSRF cookie; do not probe otherwise.
    if (!csrfCookie() || A()?.isConnected()) return;
    const { res, data } = await call("/platform/whoami");
    if (!res.ok) {
      document.cookie = "morrow_admin_csrf=; Max-Age=0; path=/; SameSite=Strict";
      if (!error) showError(res.status === 401 ? "Your console session ended. Sign in again." : messageOf(data, res));
      return;
    }
    if (data.credential_source !== "operator_session") return;
    who = data;
    proceed(data);
  }

  function proceed(data) {
    const mfa = data.mfa || {};
    if (!mfa.elevated && mfa.required && !mfa.enrolled) return startFlow("enrol");
    if (!mfa.elevated && mfa.enrolled) return startFlow("verify");
    connect(data);
  }

  function connect(data) {
    $("mfaStep").hidden = true;
    A().useSession(data.csrf_token);
    A().loadPortal().catch(A().reportLoadError);
  }

  async function startFlow(mode) {
    flow = { mode, recovery: false };
    $("ssoSlot").hidden = true;
    $("keyDisclosure").hidden = true;
    $("mfaStep").hidden = false;
    $("mfaCodes").hidden = true;
    $("mfaRecoveryField").hidden = true;
    $("mfaCodeField").hidden = false;
    $("mfaUseRecovery").hidden = mode !== "verify";
    $("mfaSubmit").textContent = "Verify";
    $("mfaCode").value = "";
    $("mfaEnrol").hidden = mode !== "enrol";
    if (mode === "enrol") {
      $("mfaTitle").textContent = "Set up your authenticator";
      $("mfaCopy").textContent = "MFA is required for platform operators. Scan the code with an authenticator app (Google Authenticator, Microsoft Authenticator, 1Password, Okta Verify), then enter the 6-digit code it shows.";
      const { res, data } = await call("/platform/mfa/enroll/start", { method: "POST", csrf: who?.csrf_token });
      if (!res.ok) { showError(messageOf(data, res)); return; }
      $("mfaQr").src = data.qr_svg_data_uri || "";
      $("mfaQr").hidden = !data.qr_svg_data_uri;
      $("mfaSecret").textContent = String(data.secret || "").replace(/(.{4})/g, "$1 ").trim();
    } else {
      $("mfaTitle").textContent = "Enter your authenticator code";
      $("mfaCopy").textContent = `Signed in as ${who?.email || who?.operator || "operator"}. Enter the 6-digit code from your authenticator app.`;
    }
    $("mfaCode").focus();
  }

  async function refreshWho() {
    const { res, data } = await call("/platform/whoami");
    if (!res.ok) throw new Error(messageOf(data, res));
    who = data;
    return data;
  }

  async function submitFlow(event) {
    event.preventDefault();
    if (!flow) return;
    showError("");
    if (flow.mode === "codes") { connect(await refreshWho()); return; }
    const body = flow.recovery ? { recovery_code: $("mfaRecovery").value.trim() } : { code: $("mfaCode").value.trim() };
    if (!flow.recovery && !/^\d{6}$/.test(body.code)) { showError("Enter the 6 digits from your authenticator app."); $("mfaCode").focus(); return; }
    const path = flow.mode === "enrol" ? "/platform/mfa/enroll/confirm" : "/platform/mfa/verify";
    $("mfaSubmit").disabled = true;
    try {
      const { res, data } = await call(path, { method: "POST", json: body, csrf: who?.csrf_token });
      if (!res.ok) {
        showError(messageOf(data, res));
        if (codeOf(data) === "session_revoked" || res.status === 401 && !codeOf(data).startsWith("mfa")) location.replace("/vendor-admin/");
        return;
      }
      if (flow.mode === "enrol") {
        flow = { mode: "codes" };
        $("mfaEnrol").hidden = true;
        $("mfaCodeField").hidden = true;
        $("mfaTitle").textContent = "Save your recovery codes";
        $("mfaCopy").textContent = "Your authenticator is set up.";
        renderCodes("mfaCodesList", data.recovery_codes);
        $("mfaCodes").hidden = false;
        $("mfaSubmit").textContent = "I saved them — continue";
        return;
      }
      connect(await refreshWho());
    } catch (err) {
      showError(err.message || String(err));
    } finally { $("mfaSubmit").disabled = false; }
  }

  function renderCodes(listId, codes) {
    $(listId).innerHTML = (codes || []).map(code => `<li>${esc(code)}</li>`).join("");
  }

  // ── Step-up for destructive actions (index.js api() calls this on mfa_step_up_required) ──
  async function stepUp(message) {
    const admin = A();
    if (!admin) return false;
    const values = await admin.openDialog({
      title: "Confirm with your authenticator",
      body: message || "This action needs a fresh authenticator code.",
      fields: [{ name: "code", label: "Authenticator code (or a recovery code)" }],
      submitLabel: "Verify and continue",
      validate: v => (/^\d{6}$/.test(String(v.code || "").trim()) || String(v.code || "").trim().length >= 10 ? "" : "Enter the 6-digit code or a recovery code."),
    });
    if (!values) return false;
    const code = String(values.code || "").trim();
    try {
      await admin.api("/platform/mfa/verify", { method: "POST", json: /^\d{6}$/.test(code) ? { code } : { recovery_code: code }, noRole: true });
      return true;
    } catch (err) {
      admin.setStatus(err.message || String(err), "bad");
      return false;
    }
  }

  // ── Operator menu, Operators page and Sessions page ─────────────────────────
  function renderMenu(data) {
    const slot = $("authMenuSlot");
    if (!slot || !data) return;
    const mfa = data.mfa || {};
    const mfaText = mfa.enrolled ? (mfa.elevated ? "verified" : "enrolled") : (mfa.required ? "required, not enrolled" : mfa.can_enrol ? "not enrolled" : "not available for a shared key");
    const session = data.session;
    slot.innerHTML = `<dl class="authMeta">
      <dt>Signed in with</dt><dd>${esc(METHOD_LABEL[data.auth_method] || data.auth_method || "key")}</dd>
      <dt>MFA</dt><dd><span class="pill ${mfa.enrolled ? "ok" : mfa.required ? "bad" : "warn"}">${esc(mfaText)}</span></dd>
      ${session ? `<dt>Session expires</dt><dd>${esc(fmtTime(session.expires_at))}</dd><dt>Ends at the latest</dt><dd>${esc(fmtTime(session.absolute_expires_at))}</dd>` : ""}
    </dl>${data.break_glass ? `<p class="authWarn">Break-glass access: every request is audited with severity high.</p>` : ""}`;
    slot.hidden = false;
    renderMfaCard(data);
  }

  function renderMfaCard(data) {
    const body = $("mfaStatusBody");
    if (!body || !data) return;
    const mfa = data.mfa || {};
    const rows = [
      ["Identity", data.email || data.operator],
      ["Signed in with", METHOD_LABEL[data.auth_method] || data.auth_method],
      ["Enrolled", mfa.enrolled ? `yes, since ${fmtTime(mfa.confirmed_at)}` : "no"],
      ["Recovery codes left", mfa.enrolled ? String(mfa.recovery_codes_remaining ?? 0) : ""],
      ["Last verified", mfa.last_verified_at ? fmtTime(mfa.last_verified_at) : ""],
      ["Policy", mfa.required ? "MFA required for operators" : "MFA optional in this environment"],
    ];
    body.innerHTML = (A() ? A().kv(rows) : "") + (mfa.can_enrol ? "" : `<p class="formNote">MFA belongs to a person. Sign in with SSO or a named operator key to enrol; the shared key cannot.</p>`) + `<div class="mfaInline" id="mfaInline" hidden></div>`;
    $("mfaEnrolBtn").disabled = !mfa.can_enrol || !!mfa.enrolled;
    $("mfaRegenBtn").disabled = !mfa.enrolled;
  }

  async function inlineEnrol() {
    const admin = A();
    const data = await admin.api("/platform/mfa/enroll/start", { method: "POST", noRole: true });
    const host = $("mfaInline");
    host.hidden = false;
    host.innerHTML = `<div class="mfaEnrol"><img src="${esc(data.qr_svg_data_uri)}" alt="QR code for your authenticator app" width="196" height="196">
      <div><span class="label">Or type this key</span><code class="mono">${esc(String(data.secret).replace(/(.{4})/g, "$1 ").trim())}</code></div></div>
      <form class="row" id="mfaInlineForm"><input id="mfaInlineCode" inputmode="numeric" autocomplete="one-time-code" maxlength="6" aria-label="Authenticator code"><button class="btn" type="submit">Confirm</button></form>`;
    $("mfaInlineForm").addEventListener("submit", admin.run(async event => {
      event.preventDefault();
      const result = await admin.api("/platform/mfa/enroll/confirm", { method: "POST", json: { code: $("mfaInlineCode").value.trim() }, noRole: true });
      host.innerHTML = `<p class="formNote ok">Authenticator enrolled. Save these recovery codes now; each works once.</p><ol class="mono mfaCodeList" id="mfaInlineCodes"></ol>`;
      renderCodes("mfaInlineCodes", result.recovery_codes);
      await refreshIdentity();
    }));
    $("mfaInlineCode").focus();
  }

  async function regenerateCodes() {
    const admin = A();
    const values = await admin.openDialog({ title: "Regenerate recovery codes", body: "Your current recovery codes stop working.", fields: [{ name: "code", label: "Authenticator code" }], submitLabel: "Regenerate", validate: v => (/^\d{6}$/.test(String(v.code || "").trim()) ? "" : "Enter the 6-digit code.") });
    if (!values) return;
    const result = await admin.api("/platform/mfa/recovery-codes/regenerate", { method: "POST", json: { code: values.code.trim() }, noRole: true });
    const host = $("mfaInline");
    host.hidden = false;
    host.innerHTML = `<p class="formNote ok">New recovery codes. Save them now; each works once.</p><ol class="mono mfaCodeList" id="mfaInlineCodes"></ol>`;
    renderCodes("mfaInlineCodes", result.recovery_codes);
    await refreshIdentity();
  }

  async function refreshIdentity() {
    const data = await A().api("/platform/whoami", { noRole: true });
    who = data;
    renderMenu(data);
  }

  let mfaOperators = [];
  async function loadMfaOperators() {
    const admin = A();
    const body = $("mfaOperatorsBody");
    if (!admin?.isConnected() || !body) return;
    if (!admin.isOwner()) { body.innerHTML = admin.empty("Owners can load MFA enrolments."); return; }
    try {
      const data = await admin.api("/platform/mfa/operators");
      mfaOperators = data.items || [];
      body.innerHTML = mfaOperators.length ? mfaOperators.map((item, index) => `<div class="event"><b class="mono">${esc(item.identity)}</b><span>${esc(item.status)} · last verified ${esc(fmtTime(item.last_verified_at))} · ${esc(item.recovery_codes_remaining)} recovery codes</span><div class="row"><button class="btn danger small" type="button" data-owner data-mfa-reset="${index}">Reset MFA&hellip;</button></div></div>`).join("") : admin.empty("No operator has enrolled MFA yet.");
      admin.applyRoleControls();
    } catch (err) { body.innerHTML = admin.failBox(`MFA enrolments unavailable: ${err.message}`, "mfa-operators"); }
  }

  let operatorSessions = [];
  async function loadOperatorSessions() {
    const admin = A();
    const body = $("operatorSessionsBody");
    if (!admin?.isConnected() || !body) return;
    try {
      const data = await admin.api("/platform/operator-sessions");
      operatorSessions = data.items || [];
      body.innerHTML = operatorSessions.length ? operatorSessions.map((s, index) => `<tr>
        <td><div class="cellStack"><b>${esc(s.email || s.operator)}</b><span class="mono muted">${esc(s.ip || "")}</span></div></td>
        <td>${esc(s.role)}</td><td>${esc(METHOD_LABEL[s.auth_method] || s.auth_method)}</td>
        <td>${s.mfa_verified_at ? `<span class="pill ok">verified</span>` : `<span class="pill warn">not verified</span>`}</td>
        <td class="mono">${esc(fmtTime(s.last_seen_at))}</td><td class="mono">${esc(fmtTime(s.expires_at))}</td>
        <td><button class="btn danger small" type="button" data-write data-operator-session="${index}">Revoke&hellip;</button></td></tr>`).join("") : admin.emptyRow(7, "No operator is signed in with SSO right now.");
      admin.applyRoleControls();
    } catch (err) { body.innerHTML = admin.failRow(7, `Operator sessions unavailable: ${err.message}`, "operator-sessions"); }
  }

  function pageLoads() {
    const hash = location.hash;
    if (hash.startsWith("#/sessions")) loadOperatorSessions();
    if (hash.startsWith("#/operators")) { loadMfaOperators(); if (who) renderMfaCard(who); }
  }

  function wire() {
    $("mfaStep")?.addEventListener("submit", submitFlow);
    $("mfaUseRecovery")?.addEventListener("click", () => {
      if (!flow) return;
      flow.recovery = !flow.recovery;
      $("mfaRecoveryField").hidden = !flow.recovery;
      $("mfaCodeField").hidden = flow.recovery;
      $("mfaUseRecovery").textContent = flow.recovery ? "Use an authenticator code" : "Use a recovery code";
      (flow.recovery ? $("mfaRecovery") : $("mfaCode")).focus();
    });
    $("mfaCancel")?.addEventListener("click", async () => {
      await call("/platform/session/logout", { method: "POST", csrf: who?.csrf_token }).catch(() => {});
      location.replace("/vendor-admin/");
    });
    document.addEventListener("admin:identity", event => { if (event.detail) { who = event.detail; renderMenu(event.detail); } });
    document.addEventListener("admin:connected", pageLoads);
    window.addEventListener("hashchange", pageLoads);
    $("operatorSessionsBtn")?.addEventListener("click", () => loadOperatorSessions());
    $("mfaOperatorsBtn")?.addEventListener("click", () => loadMfaOperators());
    $("mfaRefreshBtn")?.addEventListener("click", () => refreshIdentity().catch(err => A()?.setStatus(err.message, "bad")));
    $("mfaEnrolBtn")?.addEventListener("click", () => inlineEnrol().catch(err => A()?.setStatus(err.message, "bad")));
    $("mfaRegenBtn")?.addEventListener("click", () => regenerateCodes().catch(err => A()?.setStatus(err.message, "bad")));
    document.addEventListener("click", event => {
      const retry = event.target.closest("[data-retry]");
      if (retry?.dataset.retry === "operator-sessions") loadOperatorSessions();
      if (retry?.dataset.retry === "mfa-operators") loadMfaOperators();
    });
    $("operatorSessionsBody")?.addEventListener("click", async event => {
      const button = event.target.closest("[data-operator-session]");
      const s = button && operatorSessions[Number(button.dataset.operatorSession)];
      if (!s) return;
      const admin = A();
      const values = await admin.openDialog({ title: `Revoke ${s.email || s.operator}'s console session`, body: "They are signed out on their next request and must sign in with SSO again.", reason: true, submitLabel: "Revoke session", danger: true });
      if (!values) return;
      try {
        await admin.api(`/platform/operator-sessions/${encodeURIComponent(s.session_ref)}/revoke`, { method: "POST", json: { reason: values.reason } });
        admin.setStatus(`Revoked ${s.email || s.operator}'s console session.`, "ok");
        await loadOperatorSessions();
      } catch (err) { admin.setStatus(err.message || String(err), "bad"); }
    });
    $("mfaOperatorsBody")?.addEventListener("click", async event => {
      const button = event.target.closest("[data-mfa-reset]");
      const item = button && mfaOperators[Number(button.dataset.mfaReset)];
      if (!item) return;
      const admin = A();
      const values = await admin.openDialog({ title: `Reset MFA for ${item.identity}`, body: "Their authenticator and recovery codes stop working and their console sessions end. They enrol again at next sign-in.", reason: true, submitLabel: "Reset MFA", danger: true });
      if (!values) return;
      try {
        const result = await admin.api("/platform/mfa/reset", { method: "POST", json: { identity: item.identity, reason: values.reason } });
        admin.setStatus(`MFA reset for ${item.identity}; ${result.sessions_revoked} session(s) ended.`, "ok");
        await loadMfaOperators();
      } catch (err) { admin.setStatus(err.message || String(err), "bad"); }
    });
  }

  window.AdminAuth = { stepUp, config: () => config, identity: () => who, loadOperatorSessions, loadMfaOperators };
  wire();
  boot().catch(err => showError(err.message || String(err)));
})();
