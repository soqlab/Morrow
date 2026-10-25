const { chromium } = require("../.tools/video/node_modules/playwright");
const assert = require("node:assert/strict");
const base = (process.env.MORROW_E2E_BASE_URL || "http://127.0.0.1:8001").replace(/\/$/, "");
const key = process.env.MORROW_E2E_PLATFORM_KEY;
if (!key) throw new Error("MORROW_E2E_PLATFORM_KEY is required for authenticated workspace checks.");

// The portal's navigation is grouped dropdown menus; open the group, then pick the page.
async function openPage(page, group, route) {
  await page.locator(`.sh-top[data-top="${group}"]`).click();
  await page.locator(`.sh-link[data-route="${route}"]`).click();
  await page.locator(`[data-page="${route}"]`).waitFor();
}
// Role switch, remember and sign-out live in the operator menu at the top right.
async function openOperatorMenu(page) {
  if (!(await page.locator("#operatorPanel").isVisible())) await page.locator("#operatorMenuBtn").click();
}

async function main() {
  let browser;
  try { browser = await chromium.launch({ headless: true }); }
  catch { browser = await chromium.launch({ headless: true, channel: "chrome" }); }
  try {
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, reducedMotion: "reduce" });
    const page = await context.newPage();
    const errors = [];
    page.on("pageerror", error => errors.push(error.message));
    await page.goto(base + "/");
    const links = await page.locator('a[href^="/"]').evaluateAll(nodes => [...new Set(nodes.map(node => node.getAttribute("href").split("#")[0]))]);
    for (const link of links) {
      const response = await context.request.get(base + link);
      assert.equal(response.status(), 200, `Public destination ${link}`);
    }
    await page.locator("#menuToggle").click();
    assert.equal(await page.locator("#siteMenu").isVisible(), true);
    await page.keyboard.press("Escape");
    assert.equal(await page.locator("#siteMenu").isVisible(), false);
    console.log("Public navigation and destination checks passed.");

    assert.equal((await context.request.get(base + "/platform/customers")).status(), 403);
    await page.goto(base + "/vendor-admin/");
    await page.locator("#platformKey").fill(key);
    await page.locator("#loadBtn").click();
    await page.waitForFunction(() => document.querySelector("#apiState").textContent === "API connected", { timeout: 45000 });
    const gateResponse = await context.request.get(base + "/platform/go-live-gate", { headers: { "x-platform-key": key } });
    const gate = await gateResponse.json();
    const gateText = await page.locator("#gateBody").innerText();
    assert.ok(gateText.includes(`${gate.failed_required_checks.length} blocker(s)`), "Gate must display actual backend blocker count");
    if (gate.failed_required_checks.length) assert.equal(gateText.includes("Nothing outstanding"), false);
    await openPage(page, "security", "launch");
    await openOperatorMenu(page);
    await page.locator("#platformRole").selectOption("auditor");
    assert.equal(await page.locator("#quickTenantBtn").isDisabled(), true);
    assert.equal(await page.locator("#saveCustomerBtn").isDisabled(), true);
    await page.locator("#platformRole").selectOption("owner");
    await page.keyboard.press("Escape");
    assert.equal(await page.locator("#readinessBody").isVisible(), true);
    assert.equal(await page.locator("#customersBody").isVisible(), false);
    await openPage(page, "customers", "feedback");
    assert.equal(await page.locator("#feedbackBody").isVisible(), true);
    await openPage(page, "customers", "customers");
    await page.locator("#searchBox").fill("unmatched-customer-workspace-smoke");
    assert.ok((await page.locator("#customersBody").innerText()).includes("No customers match"));
    await page.locator("#searchBox").fill("");

    const row = page.locator("#customersBody .customerRow").first();
    if (await row.count()) {
      let suspended = 0;
      page.on("request", request => { if (request.method() === "POST" && /\/suspend$/.test(request.url())) suspended++; });
      await row.focus();
      await page.keyboard.press("Enter");
      // A row opens the organization's Customer 360; its Manage action opens the customer drawer.
      await page.locator("#c360EditBtn").waitFor();
      await page.locator("#c360EditBtn").click();
      await page.locator("#drawer.open").waitFor();
      page.once("dialog", dialog => dialog.dismiss());
      await page.locator("#suspendBtn").click();
      await page.waitForTimeout(250);
      assert.equal(suspended, 0, "Cancelling must never submit a suspension");
      await page.keyboard.press("Escape");
      assert.equal(await page.locator("#drawer").getAttribute("aria-hidden"), "true");
      assert.equal(await page.locator(".adminWorkspace").evaluate(el => el.inert), false);
    }
    await page.route("**/platform/health", route => route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ detail: "Simulated unavailable dependency" }) }));
    await page.locator("#reloadAllBtn").click();
    await page.waitForFunction(() => document.querySelector("#apiState").textContent === "API partially available");
    assert.equal(await page.locator("#mHealthState").innerText(), "Unknown");
    assert.equal(await page.locator("#mOpenAlerts").innerText(), "--");
    await page.unroute("**/platform/health");
    await openOperatorMenu(page);
    await page.locator("#saveBtn").click();
    await page.waitForFunction(() => !!sessionStorage.getItem("morrow_platform_admin_key"));
    assert.equal(await page.evaluate(() => localStorage.getItem("morrow_platform_key") || localStorage.getItem("morrow_platform_admin_key")), null);
    await openOperatorMenu(page);
    await page.locator("#clearBtn").click();
    await page.waitForFunction(() => !sessionStorage.getItem("morrow_platform_admin_key") && document.querySelector("#mCustomers").textContent === "--");
    assert.equal(await page.locator("#customersBody .customerRow").count(), 0);
    assert.equal(await page.locator("#platformKey").inputValue(), "");
    console.log("Admin navigation, real gate, dependency failure, cancellation, and sign-out checks passed.");

    await page.goto(base + "/vendor-admin/traffic.html");
    await page.locator("#platformKey").fill(key);
    await page.locator("#refreshBtn").click();
    await page.waitForFunction(() => document.querySelector("#apiState").textContent === "Connected");
    await page.locator("#pathFilter").fill("/route-that-does-not-exist-workspace-smoke");
    await page.locator("#eventsBtn").click();
    await page.waitForFunction(() => document.querySelector("#eventsBody").textContent.includes("No matching events"));
    await page.locator("#refreshBtn").click();
    await page.waitForFunction(() => document.querySelector("#status").textContent.startsWith("Snapshot"));
    assert.ok((await page.locator("#eventsBody").innerText()).includes("No matching events"), "Refresh preserves event filters");
    await page.locator("#saveBtn").click();
    await page.waitForFunction(() => !!sessionStorage.getItem("morrow_platform_admin_key"));
    assert.equal(await page.evaluate(() => localStorage.getItem("morrow_platform_key")), null);
    await page.locator("#signOutBtn").click();
    await page.waitForFunction(() => !sessionStorage.getItem("morrow_platform_admin_key") && document.querySelector("#mEvents").textContent === "--");
    console.log("Traffic filters and credential cleanup checks passed.");

    for (const path of ["/", "/ui/", "/vendor-admin/", "/vendor-admin/traffic.html", "/security", "/pricing", "/enterprise-admin", "/trust-passport-demo"]) {
      await page.setViewportSize({ width: 390, height: 844 });
      await page.goto(base + path, { waitUntil: "domcontentloaded" });
      await page.waitForTimeout(500);
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, `Mobile overflow: ${path}`);
    }
    assert.deepEqual(errors, [], "Uncaught browser exceptions");
    console.log("Mobile layout checks passed. Admin workspace smoke passed.");
  } finally { await browser.close(); }
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
