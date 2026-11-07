// Console happy path against the e2e stack (after backend/e2e_real has run for the same org):
//   Asset Inventory › Passive discovery lists what Fluent Bit / Vector shipped,
//   Scanners › VPN (IKEv2) scans the real strongSwan responder from the browser,
//   CBOM shows the imported CBOMkit inventory.
//
//   MORROW_E2E_BASE_URL=http://127.0.0.1:18000 MORROW_E2E_ORG=e2e-demo-org \
//   PLAYWRIGHT_MODULE=<path to node_modules/playwright> node deploy/e2e/console-smoke.js
//
// The backend runs MORROW_AUTH_MODE=headers, so the console identity is the org / actor / role the
// sign-in panel stores in localStorage. Screenshots go to deploy/e2e/state/screens/.
const path = require("node:path");
const fs = require("node:fs");
const assert = require("node:assert/strict");
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || "playwright");

const base = (process.env.MORROW_E2E_BASE_URL || "http://127.0.0.1:18000").replace(/\/$/, "");
const org = process.env.MORROW_E2E_ORG;
assert.ok(org, "set MORROW_E2E_ORG to the organization the e2e tests used");
const shots = path.join(__dirname, "state", "screens");
// "load" waits for every font and script; a busy backend can take minutes to serve them all.
const NAV = { waitUntil: "domcontentloaded", timeout: 600000 };
fs.mkdirSync(shots, { recursive: true });

async function main() {
  let browser;   // the bundled headless shell, else an installed Chrome (as scripts/*-smoke.js do)
  try { browser = await chromium.launch({ headless: true }); }
  catch { browser = await chromium.launch({ headless: true, channel: "chrome" }); }
  const errors = [];
  try {
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, reducedMotion: "reduce" });
    await context.addInitScript(([o]) => {
      localStorage.setItem("pq_org", o);
      localStorage.setItem("pq_actor", "e2e-console");
      localStorage.setItem("morrow_role", "admin");
    }, [org]);
    const page = await context.newPage();
    page.setDefaultTimeout(180000);
    page.on("pageerror", e => errors.push(e.message));

    await page.goto(base + "/ui/#assets", NAV);
    await page.locator("#passiveBox").getByText("envoy.e2e.morrow.test").first().waitFor();
    await page.locator("#passiveBox").getByText("X25519MLKEM768").first().waitFor();
    await page.screenshot({ path: path.join(shots, "passive-discovery.png"), fullPage: true });
    console.log("ok  Asset Inventory > Passive discovery shows the shipped Envoy/nginx endpoints");

    await page.goto(base + "/ui/#scanners", NAV);
    await page.locator('[data-tabs="sn"] .tab[data-key="vpn"]').click();
    await page.locator("#ikeTg").fill("vpn.e2e.morrow.test");
    await page.locator('[data-act="ikeScan"]').click();
    await page.locator("#ikeOut").getByText("ML_KEM_768").first().waitFor({ timeout: 360000 });
    await page.screenshot({ path: path.join(shots, "ike-scan.png"), fullPage: true });
    console.log("ok  Scanners > VPN (IKEv2) scan of vpn.e2e.morrow.test reports ML_KEM_768");

    await page.goto(base + "/ui/#cbom", NAV);
    await page.locator("#view").getByText(/cbomkit/i).first().waitFor();
    await page.screenshot({ path: path.join(shots, "cbom.png"), fullPage: true });
    console.log("ok  CBOM view lists the CBOMkit import");

    assert.deepEqual(errors, [], "no page errors");
  } finally {
    await browser.close();
  }
}

main().catch(e => { console.error("::error title=console-smoke::" + (e && e.message || e)); process.exit(1); });
