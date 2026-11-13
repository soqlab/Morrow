// Sign-up, joining and recovery without email, in a real browser.
//
// CI's server has no MORROW_PUBLIC_BASE_URL, so passkeys are off there and every page has to say
// so plainly. What is checked:
//   - /signup, /join and /reset-password load, contact only this origin and throw no errors, and have
//     no horizontal overflow at phone width;
//   - with passkeys off, /signup says sign-up isn't open and points at sign-in;
//   - with sign-up open (the hosted /auth/config, mocked) the whole flow runs: nothing to type but an
//     optional name and organization, one passkey ceremony (the browser half is stubbed: CI has no
//     relying party), the recovery codes shown once and kept in no storage, "saved" required before
//     going on, and /signup?watch=<domain> watches that domain and lands back on /<domain>;
//   - /join without a link on a server that emails nothing asks for an invite link;
//   - /reset-password with no codes and no mail is "Lost your passkey?" and points at an admin;
//   - a signed-out visitor's Watch button on /<domain> leads to /signup?watch=<domain>.
const { chromium } = require("../.tools/video/node_modules/playwright");
const assert = require("node:assert/strict");
const base = (process.env.MORROW_E2E_BASE_URL || "http://127.0.0.1:8001").replace(/\/$/, "");
const origin = new URL(base).origin;

const DOMAIN = "signup-smoke.example";
const CODES = ["ABCD-EFGH-JKMN-PQRS", "TUVW-XYZ2-3456-789A", "BCDE-FGHJ-KMNP-QRST", "UVWX-YZ23-4567-89AB",
  "CDEF-GHJK-MNPQ-RSTU", "VWXY-Z234-5678-9ABC", "DEFG-HJKM-NPQR-STUV", "WXYZ-2345-6789-ABCD",
  "EFGH-JKMN-PQRS-TUVW", "XYZ2-3456-789A-BCDE"];
const SMOKE_GRADE = {
  domain: DOMAIN, scanned_at: new Date().toISOString(), cached: false, grade: "C",
  summary: "classical", summaries: { executive: "classical", cryptographer: "x25519 only" },
  tls: { versions: { "1.3": true, "1.2": true, "1.1": false, "1.0": false }, negotiated: "TLSv1.3", untested: [] },
  key_exchange: { group: "x25519", post_quantum: false, hybrid: false, offered_pq_groups_accepted: [], observed: true },
  certificate: { key_type: "EC", key_bits: 256, signature_algorithm: "ecdsa-with-SHA256", not_after: "2027-01-01T00:00:00Z", issuer: "CN=Test", verified: true },
  forward_secrecy: true, server_software: "nginx", platform: "nginx",
  exposure: { recorded_traffic_at_risk: true, decrypt_year_low: 2035, decrypt_year_high: 2040, basis: "basis", source_url: "https://globalriskinstitute.org/" },
  fixes: [{ title: "Turn on X25519MLKEM768", snippet: "ssl_ecdh_curve X25519MLKEM768:X25519;", notes: "", requires: "OpenSSL 3.5", applies_to: "nginx" }],
  reasons: ["TLS 1.3 with classical key exchange only (x25519)."], rubric_version: "test", connections: 9, notes: [],
};
const SMOKE_EXPOSURE = {
  domain: DOMAIN, checked_at: new Date().toISOString(), cached: false,
  homepage: { url: `https://${DOMAIN}/`, read: true, notes: [] },
  own: { grade: "C", post_quantum: false, key_exchange: "x25519" },
  services: [
    { host: "js.stripe.com", role: "payment", vendor: "Stripe", via: "script on the homepage", status: "classical", key_exchange: "x25519", readable_from: 2035, fix: "Ask Stripe when js.stripe.com will offer X25519MLKEM768." },
    { host: "fonts.googleapis.com", role: "fonts", vendor: "Google Fonts", via: "stylesheet on the homepage", status: "pq", key_exchange: "X25519MLKEM768", readable_from: null, fix: "Nothing to ask for." },
  ],
  counts: { found: 2, probed: 2, exposed: 1, graded: 2, over_cap: 0 }, probed: 2, limits: { max_hosts: 12 },
  summaries: { plain: "You're not ready yet, and neither is your payment provider (js.stripe.com).",
    standard: "You're ready, but your payment provider isn't (js.stripe.com).", expert: "1/2 graded third-party hosts are classical." },
};
async function routeDomain(page) {
  await page.route(`**/api/public/grade/${DOMAIN}*`, (r) => r.fulfill({ json: SMOKE_GRADE }));
  await page.route(`**/api/public/history/${DOMAIN}*`, (r) => r.fulfill({ json: [] }));
  await page.route(`**/api/public/exposure/${DOMAIN}*`, (r) => r.fulfill({ json: SMOKE_EXPOSURE }));
}
// The browser half of the ceremony, stubbed: what /ui/passkey.js exposes, minus navigator.credentials.
const FAKE_PASSKEY = `window.MorrowPasskey = Object.freeze({
  supported: () => true, conditionalAvailable: async () => false, message: () => "",
  create: async (options) => ({ id: "c3R1Yg", rawId: "c3R1Yg", type: "public-key", clientExtensionResults: {},
    response: { clientDataJSON: "e30", attestationObject: "o2Nmb3Jt", transports: ["internal"] }, rp: options.rp.id }),
  get: async () => { throw new Error("not used"); } });`;

async function main() {
  const browser = await chromium.launch({ headless: true });
  const errors = [];
  const foreign = [];
  const watch = (page) => {
    page.on("pageerror", (e) => errors.push(String(e)));
    page.on("request", (r) => { const u = r.url(); if (!u.startsWith(origin) && !u.startsWith("data:") && !u.startsWith("blob:")) foreign.push(u); });
  };
  try {
    // 1. As CI's server really is: no passkeys, so no sign-up.
    const plain = await browser.newContext({ viewport: { width: 1280, height: 860 } });
    const page = await plain.newPage();
    watch(page);
    await page.goto(`${base}/signup`, { waitUntil: "networkidle" });
    await page.locator("#signupTitle", { hasText: "Sign-up isn't open here." }).waitFor({ timeout: 15000 });
    assert.equal(await page.locator('#signupState a[href="/ui/"]').count(), 1, "/signup offers no way to sign in");

    await page.goto(`${base}/join`, { waitUntil: "networkidle" });
    await page.locator("#joinLead", { hasText: "Ask an admin of your organization for an invite link" }).waitFor({ timeout: 15000 });
    assert.equal(await page.locator("#joinEmailInput").count(), 0, "/join asks for an email address");
    assert.equal(await page.locator('#joinState a[href="/signup"]').count(), 1);

    await page.goto(`${base}/reset-password`, { waitUntil: "networkidle" });
    await page.locator("#resetTitle", { hasText: "Lost your passkey?" }).waitFor({ timeout: 15000 });
    assert.match(await page.locator("#resetLead").innerText(), /admin of your organization/);
    assert.equal(await page.locator("#resetEmail").count(), 0, "/reset-password asks for an email address");

    // 2. The hosted configuration: sign-up open. Config and ceremony mocked; the watch is real.
    const hosted = await browser.newContext({ viewport: { width: 1280, height: 860 } });
    const flow = await hosted.newPage();
    watch(flow);
    const seen = { begin: null, finish: 0, watch: 0 };
    await flow.route("**/auth/config", (r) => r.fulfill({ json: { mode: "jwt", signup_enabled: true, passkeys_enabled: true, passkeys_only: true } }));
    await flow.route("**/ui/passkey.js*", (r) => r.fulfill({ body: FAKE_PASSKEY, contentType: "text/javascript" }));
    await flow.route("**/auth/passkey/register/begin", async (r) => {
      seen.begin = r.request().postDataJSON();
      await r.fulfill({ json: { challenge_id: "smoke-challenge-0001", options: { rp: { id: "morrow.example", name: "Morrow" }, user: { id: "dQ", name: "x", displayName: "x" }, challenge: "Y2hhbA", pubKeyCredParams: [] } } });
    });
    await flow.route("**/auth/passkey/register/finish", (r) => { seen.finish += 1; return r.fulfill({ json: {
      access_token: "smoke-access", refresh_token: "smoke-refresh", token_type: "bearer", recovery_codes: CODES,
      organization: { id: "org_smoke", name: "Smoke Labs" }, user: { id: "u", org_id: "org_smoke", role: "admin" } } }); });
    await flow.route(`**/instrument/watch/${DOMAIN}`, (r) => {
      if (r.request().method() === "PUT") { seen.watch += 1; assert.equal(r.request().headers().authorization, "Bearer smoke-access"); }
      return r.fulfill({ json: { domain: DOMAIN, watching: true } });
    });
    await routeDomain(flow);
    await flow.goto(`${base}/signup?watch=${DOMAIN}`, { waitUntil: "networkidle" });
    await flow.locator("#signupTitle", { hasText: `Watch ${DOMAIN}.` }).waitFor({ timeout: 15000 });
    assert.equal(await flow.locator('#signupState input[type="email"], #signupState input[type="password"]').count(), 0);
    const trap = await flow.locator("#signupWebsite").boundingBox();
    assert.ok(!trap || trap.x + trap.width <= 0 || trap.width <= 1, "the hidden field is on screen");
    await flow.locator("#signupOrg").fill("Smoke Labs");
    await flow.locator("#signupState button", { hasText: "Create passkey and account" }).click();
    await flow.locator("#signupCodes li").first().waitFor({ timeout: 15000 });
    assert.deepEqual(seen.begin, { kind: "signup", full_name: "", organization: "Smoke Labs", website: "" });
    assert.equal(await flow.locator("#signupCodes li").count(), 10);
    assert.equal(await flow.locator("#signupCodes li").first().innerText(), CODES[0]);
    const kept = await flow.evaluate(() => JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage }) + location.href);
    assert.ok(!kept.includes(CODES[0]), "a recovery code was kept in storage or the address");
    assert.equal(await flow.evaluate(() => localStorage.getItem("morrow_token")), "smoke-access");
    // Going on needs the box ticked.
    await flow.locator("#signupState button", { hasText: `Continue to ${DOMAIN}` }).click();
    assert.match(await flow.locator("#signupError").innerText(), /Tick the box/);
    assert.equal(seen.watch, 0);
    await flow.locator("#signupSaved").check();
    await Promise.all([flow.waitForURL(`${base}/${DOMAIN}`, { timeout: 15000 }), flow.locator("#signupState button", { hasText: `Continue to ${DOMAIN}` }).click()]);
    assert.equal(seen.watch, 1, "the domain wasn't watched after sign-up");
    assert.equal(seen.finish, 1);

    // 3. Signed out on a domain page, Watch leads to sign-up with the domain.
    const anon = await browser.newContext({ viewport: { width: 1280, height: 860 } });
    const domainPage = await anon.newPage();
    watch(domainPage);
    await routeDomain(domainPage);
    // CI's server needs no sign-in; a hosted one answers 401 to a browser without a session.
    await domainPage.route("**/scans?limit=100*", (r) => r.fulfill({ status: 401, json: { detail: "Bearer token required" } }));
    await domainPage.goto(`${base}/${DOMAIN}`, { waitUntil: "networkidle" });
    await domainPage.locator("#w-signup").waitFor({ timeout: 15000 });
    assert.equal(await domainPage.locator("#w-signup").getAttribute("href"), `/signup?watch=${DOMAIN}`);
    assert.match(await domainPage.locator("#w-say").innerText(), /passkey/);

    // 4. The console's sign-in screen on a hosted server offers "Create an account" and no email sign-in.
    const gateCtx = await browser.newContext({ viewport: { width: 1280, height: 860 } });
    const gate = await gateCtx.newPage();
    watch(gate);
    await gate.route("**/auth/config", (r) => r.fulfill({ json: { mode: "jwt", required: true, password_login_enabled: true, bearer_token_supported: true,
      passkeys_enabled: true, passkeys_only: true, recovery_codes_enabled: true, password_reset_enabled: false, team_join_enabled: false,
      invite_links_enabled: true, signup_enabled: true, simple_sign_in: true } }));
    await gate.route("**/assets", (r) => r.fulfill({ status: 401, json: { detail: "Bearer token required" } }));
    await gate.goto(`${base}/ui/`, { waitUntil: "networkidle" });
    await gate.locator('#gate a.btn[href="/signup"]').waitFor({ timeout: 15000 });
    const gateText = await gate.locator("#gate").innerText();
    assert.match(gateText, /No account yet\? Create one, free\./);
    assert.ok(!/Request access|trial|sets one up/i.test(gateText), `the sign-in screen still says: ${gateText}`);
    await gate.locator('[data-act="gateShowRecovery"]').click();
    assert.match(await gate.locator("#gCodeBox").innerText(), /Ask an admin of your organization for a recovery link/);

    const phone = await browser.newContext({ viewport: { width: 360, height: 780 } });
    const small = await phone.newPage();
    watch(small);
    for (const path of ["/signup", "/join", "/reset-password"]) {
      await small.goto(`${base}${path}`, { waitUntil: "networkidle" });
      const wide = await small.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
      assert.ok(wide <= 1, `${path} overflows a 360px screen by ${wide}px`);
    }

    assert.deepEqual(foreign, [], "a page contacted another origin");
    assert.deepEqual(errors, [], "JavaScript errors");
    console.log("PASS: /signup closed without passkeys and open with them, codes once and kept nowhere, watch after sign-up, /join and /reset-password without email, Watch leads to sign-up, console sign-in offers sign-up, 360px layout.");
  } finally {
    await browser.close();
  }
}

main().catch((error) => { console.error(error); process.exit(1); });
