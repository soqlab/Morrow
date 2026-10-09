const { chromium } = require("../.tools/video/node_modules/playwright");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const base = (process.env.PQC_E2E_BASE_URL || "http://127.0.0.1:8001").replace(/\/$/, "");

async function main() {
  let browser;
  try { browser = await chromium.launch({ headless: true }); }
  catch { browser = await chromium.launch({ headless: true, channel: "chrome" }); }
  try {
    assert.ok(fs.readFileSync("backend/static/index.html").equals(fs.readFileSync("frontend/index.html")), "Console copies agree");
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, reducedMotion: "reduce" });
    const page = await context.newPage();
    const errors = [];
    page.on("pageerror", error => errors.push(error.message));
    await page.goto(base + "/ui/");
    await page.locator(".consoleHero").waitFor({ timeout: 60000 });
    assert.equal(await page.locator("#orgSel").count(), 1);
    assert.equal(await page.locator("#identity").count(), 1);
    assert.equal(await page.locator(".overviewMetrics .meter").count(), 0, "No invented coverage bars");
    assert.equal(await page.locator(".workspaceFold[open]").count(), 0);
    await page.locator(".workspaceFold").first().locator("summary").click();
    assert.equal(await page.locator(".modelStats").isVisible(), true);
    await page.locator(".workspaceFold").first().locator("summary").click();
    await page.locator("#navToggle").click();
    assert.ok((await page.locator("#app").getAttribute("class")).includes("collapsed"));
    await page.locator("#navToggle").click();

    await page.locator("#cmdOpen").click();
    await page.locator("#cmdQ").fill("Asset Inventory");
    await page.keyboard.press("Enter");
    await page.waitForFunction(() => document.querySelector("#vTitle").textContent === "Asset Inventory" && document.querySelector("#view").innerText.length > 40);
    await page.locator('.nav[data-go="overview"]').click();
    await page.locator(".consoleHero").waitFor({ timeout: 60000 });
    let themeFetches = 0;
    const onThemeRequest = request => { if (request.resourceType() === "fetch") themeFetches++; };
    page.on("request", onThemeRequest);
    for (const theme of ["dark", "light"]) {
      if (await page.locator("html").getAttribute("data-theme") !== theme) await page.locator("#themeBtn").click();
      await page.locator(".consoleHero").waitFor({ timeout: 60000 });
      assert.equal(await page.locator("html").getAttribute("data-theme"), theme);
      const contrast = await page.locator("#missionLive .cardHead h3").first().evaluate(el => {
        const channel = c => (c /= 255) <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
        const luminance = value => {
          const [r, g, b] = value.match(/[\d.]+/g).slice(0, 3).map(Number);
          return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
        };
        // The card paints its own dark ground in both themes; walk up to whatever
        // actually sits behind the heading.
        let ground = el, background = getComputedStyle(ground).backgroundColor;
        while (ground.parentElement && /rgba\(0, 0, 0, 0\)|transparent/.test(background)) {
          ground = ground.parentElement;
          background = getComputedStyle(ground).backgroundColor;
        }
        const a = luminance(getComputedStyle(el).color), b = luminance(background);
        return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
      });
      assert.ok(contrast >= 4.5, `Dark graph heading remains legible in both themes (${contrast.toFixed(2)}:1)`);
    }
    page.off("request", onThemeRequest);
    assert.equal(themeFetches, 0, "Theme switching does not reload customer data");
    console.log("PASS: synced console, snapshot metrics, model disclosure, command search, sidebar collapse, both themes.");

    for (const width of [320, 390, 768]) {
      await page.setViewportSize({ width, height: 900 });
      await page.locator("#navToggle").click();
      assert.equal(await page.locator(".main").evaluate(el => el.inert), true);
      assert.equal(await page.locator("#consoleSidebar").evaluate(el => el.inert), false);
      await page.locator("#navClose").focus();
      await page.keyboard.press("Shift+Tab");
      assert.equal(await page.locator("#cfgBtn").evaluate(el => el === document.activeElement), true);
      await page.keyboard.press("Tab");
      assert.equal(await page.locator("#navClose").evaluate(el => el === document.activeElement), true);
      await page.keyboard.press("Escape");
      assert.equal(await page.locator(".main").evaluate(el => el.inert), false);
      assert.equal(await page.locator("#consoleSidebar").evaluate(el => el.inert), true);
      assert.equal(await page.locator("#navToggle").getAttribute("aria-expanded"), "false");
      await page.locator("#navToggle").click();
      await page.locator('#consoleSidebar [data-go="scans"]').click();
      await page.waitForFunction(() => document.querySelector("#vTitle").textContent === "TLS Scanner" && document.querySelector("#view").innerText.length > 40);
      assert.equal(await page.locator(".main").evaluate(el => el.inert), false);
      assert.equal(await page.locator("#navBackdrop").isVisible(), false);
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), "Scanner fits width " + width);
      await page.locator("#navToggle").click();
      await page.locator('#consoleSidebar [data-go="overview"]').click();
      await page.locator(".consoleHero").waitFor({ timeout: 60000 });
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), "Overview fits width " + width);
    }
    console.log("PASS: mobile navigation, focus trap, Escape, route selection, and 320/390/768px layout.");

    await page.route("**/assets", route => route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ detail: "Test source failure" }) }));
    await page.goto(base + "/ui/");
    await page.locator(".consoleHero").waitFor({ timeout: 60000 });
    assert.equal(await page.locator(".overviewMetrics .metricRow").first().locator("b").innerText(), "—");
    assert.ok((await page.locator(".overviewMetrics").innerText()).includes("Inventory source unavailable"));
    await page.unroute("**/assets");
    for (const route of ["/security","/privacy","/terms","/support","/pricing","/pilot","/data-boundary","/airlock-deployment","/dpa","/trust-passport-demo","/enterprise-admin","/invite"]) {
      await page.goto(base + route);
      assert.equal(await page.locator('link[href*="/ui/experience.css"]').count(), 1);
      assert.equal(await page.locator(".topbar .nav .nav-cta").getAttribute("href"), "/ui/");
      for (const width of [390, 1440]) {
        await page.setViewportSize({ width, height: 900 });
        assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), route + " fits " + width);
      }
    }
    assert.deepEqual(errors, []);
    console.log("PASS: missing inventory stays unavailable, 12 public pages share navigation/styles and fit mobile/desktop, no JS errors.");
  } finally { await browser.close(); }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
