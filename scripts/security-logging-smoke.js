// Read-only UI checks against real logs. Does not create users or manufacture API data.
const { chromium } = require("../.tools/video/node_modules/playwright");
const assert = require("node:assert/strict");
const base = (process.env.MORROW_E2E_BASE_URL || "http://127.0.0.1:8001").replace(/\/$/, "");
const key = process.env.MORROW_E2E_PLATFORM_KEY;
if (!key) throw new Error("MORROW_E2E_PLATFORM_KEY is required.");

async function main() {
  let browser;
  try { browser = await chromium.launch({ headless: true }); }
  catch { browser = await chromium.launch({ headless: true, channel: "chrome" }); }
  try {
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
    const headers = { "x-platform-key": key, "x-platform-admin-role": "auditor" };
    for (const path of ["/platform/auth-events", "/platform/logging/health", "/platform/traffic/events?source=archive"]) {
      assert.ok([401, 403].includes((await context.request.get(base + path)).status()));
      assert.equal((await context.request.get(base + path, { headers })).status(), 200);
    }
    await context.request.get(base + "/status?smoke_secret=never-store-this-value");
    const page = await context.newPage();
    const errors = [];
    page.on("pageerror", error => errors.push(error.message));
    await page.goto(base + "/vendor-admin/#activity");
    await page.locator("#platformKey").fill(key);
    await page.locator("#loadBtn").click();
    await page.waitForFunction(() => document.querySelector("#loggingHealth").textContent.includes("Storage: available"));
    const filtered = page.waitForResponse(response => response.url().includes("/platform/logins?") && response.url().includes("event_type=login.failure"));
    await page.locator("#authEventType").selectOption("login.failure");
    assert.equal((await filtered).status(), 200);
    await page.goto(base + "/vendor-admin/traffic.html");
    await page.locator("#platformKey").fill(key);
    await page.locator("#platformRole").selectOption("auditor");
    await page.locator("#refreshBtn").click();
    await page.waitForFunction(() => document.querySelector("#status").textContent.startsWith("Snapshot"));
    assert.ok((await page.locator("#retentionState").innerText()).includes("Archive: available"));
    assert.equal(await page.locator("#clearTrafficBtn").isDisabled(), true);
    await page.locator("#pathFilter").fill("/status");
    const archiveResponse = page.waitForResponse(response => response.url().includes("/platform/traffic/events?") && response.url().includes("source=archive"));
    await page.locator("#historySource").selectOption("archive");
    const rows = (await (await archiveResponse).json()).items;
    assert.ok(rows.length && rows.every(row => row.path === "/status"));
    assert.equal(JSON.stringify(rows).includes("never-store-this-value"), false);
    await page.waitForFunction(() => document.querySelector("#status").textContent.includes("matching events from archive"));
    assert.ok((await page.locator("#eventsBody").innerText()).includes("/status"));
    const download = page.waitForEvent("download");
    await page.locator("#exportNdjsonBtn").click();
    assert.equal((await download).suggestedFilename(), "pq-traffic-events.ndjson");
    for (const path of ["/vendor-admin/#activity", "/vendor-admin/traffic.html"]) {
      await page.setViewportSize({ width: 390, height: 844 });
      await page.goto(base + path);
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
    }
    assert.deepEqual(errors, []);
    console.log("Security logging UI passed: protected real APIs, auth filter, archive filter, export, auditor controls and mobile layout.");
  } finally { await browser.close(); }
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
