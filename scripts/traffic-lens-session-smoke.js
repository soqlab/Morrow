// Traffic Lens with an operator session cookie (SSO cookie mode) instead of a typed platform key.
//
// Needs an existing operator session: MORROW_E2E_OPERATOR_SESSION is the raw morrow_admin_session value
// (backend/test_traffic_lens_session.py mints one with services/operator_auth.create_session). Optional:
// MORROW_E2E_OPERATOR_CSRF (the morrow_admin_csrf cookie value) and MORROW_E2E_OPERATOR_SESSION_MFA_PENDING (a
// session whose MFA check is still pending, which must be sent back to /vendor-admin/).
// Never prints the session values.
const { chromium } = require("../.tools/video/node_modules/playwright");
const assert = require("node:assert/strict");
const base = (process.env.MORROW_E2E_BASE_URL || "http://127.0.0.1:8001").replace(/\/$/, "");
const session = process.env.MORROW_E2E_OPERATOR_SESSION;
const csrfCookie = process.env.MORROW_E2E_OPERATOR_CSRF || "present";
const pending = process.env.MORROW_E2E_OPERATOR_SESSION_MFA_PENDING;
if (!session) throw new Error("MORROW_E2E_OPERATOR_SESSION is required.");

function cookies(raw) {
  const url = new URL(base);
  const common = { domain: url.hostname, path: "/", secure: url.protocol === "https:", sameSite: "Strict" };
  return [{ name: "morrow_admin_session", value: raw, httpOnly: true, ...common }, { name: "morrow_admin_csrf", value: csrfCookie, httpOnly: false, ...common }];
}

async function main() {
  let browser;
  try { browser = await chromium.launch({ headless: true, channel: "chrome" }); }
  catch { browser = await chromium.launch({ headless: true }); }
  try {
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
    await context.addCookies(cookies(session));
    const page = await context.newPage();
    const errors = [];
    const sentKeys = [];
    const writes = [];
    page.on("pageerror", error => errors.push(error.message));
    page.on("request", request => {
      const headers = request.headers();
      if (request.url().includes("/platform/") && headers["x-platform-key"]) sentKeys.push(request.url());
      if (request.url().includes("/platform/traffic/clear")) writes.push(headers["x-csrf-token"] || "");
    });
    await page.goto(base + "/vendor-admin/traffic.html");
    // No key typed: the page detects the session, loads traffic and reports the signed-in operator.
    await page.waitForFunction(() => document.body.dataset.auth === "session", null, { timeout: 30000 });
    await page.waitForFunction(() => document.querySelector("#status").textContent.startsWith("Snapshot"), null, { timeout: 60000 });
    assert.equal(await page.locator("#platformKey").isDisabled(), true, "the key field is not used in session mode");
    assert.equal(await page.locator("#saveBtn").isHidden(), true, "nothing to remember in session mode");
    await page.locator("#pathFilter").fill("/platform/traffic");
    await page.locator("#eventsBtn").click();
    await page.waitForFunction(() => document.querySelector("#status").textContent.includes("matching events"));
    // A write carries the CSRF token from /platform/whoami.
    page.once("dialog", dialog => dialog.accept());
    const cleared = page.waitForResponse(response => response.url().includes("/platform/traffic/clear"));
    assert.equal(await page.locator("#clearTrafficBtn").isDisabled(), false, "owner/operator sessions can clear");
    await page.locator("#clearTrafficBtn").click();
    assert.equal((await cleared).status(), 200);
    assert.equal(writes.length, 1);
    assert.ok(writes[0].length >= 16, "clear sent x-csrf-token");
    assert.deepEqual(sentKeys, [], "no x-platform-key header is sent in session mode");
    assert.equal(await page.evaluate(() => Object.keys(sessionStorage).filter(k => /platform/.test(k)).length), 0, "session mode stores nothing");
    assert.deepEqual(errors, []);
    console.log("Traffic Lens session mode passed: detected the operator session, loaded traffic without a key, cleared with CSRF.");

    if (pending) {
      const other = await browser.newContext();
      await other.addCookies(cookies(pending));
      const pendingPage = await other.newPage();
      await pendingPage.goto(base + "/vendor-admin/traffic.html");
      await pendingPage.waitForURL(url => new URL(url).pathname === "/vendor-admin/", { timeout: 30000 });
      console.log("Traffic Lens sends a session with MFA still pending to /vendor-admin/.");
      await other.close();
    }
  } finally { await browser.close(); }
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
