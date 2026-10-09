const assert = require("node:assert/strict");
const { chromium } = require("../.tools/video/node_modules/playwright");
const base = process.env.PQC_E2E_BASE_URL || "http://127.0.0.1:8001";

async function main() {
  let browser;
  try { browser = await chromium.launch({ headless: true }); }
  catch { browser = await chromium.launch({ headless: true, channel: "chrome" }); }
  const errors = [], writes = [];
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 }, reducedMotion: "reduce" });
    page.on("pageerror", error => errors.push(error.message));
    const sites = [];
    let failed = false;
    await page.route("**/gateway/**", async route => {
      const request = route.request(), path = new URL(request.url()).pathname;
      if (failed) return route.fulfill({ status: 503, json: { detail: "Fixture dependency unavailable" } });
      if (request.method() !== "GET") writes.push({ path, body: request.postDataJSON() });
      if (request.method() === "POST" && path.endsWith("/sites")) {
        const body = request.postDataJSON();
        sites.push({ id: "fixture-site", hostname: new URL(body.website).hostname,
          policy: { version: 1, mode: "observe", origin_url: body.origin, exceptions: [], retention_hours: 24, max_body_bytes: 1048576 },
          coverage: { ownership: "verification_required", routing: "unknown", filtering: "unknown", certificate: "unknown", visitor_pqc: "unknown", origin_pqc: "unknown", basis: "Browser test fixture only" },
          dns_records: [{ name: "_airlock-gateway.fixture.customer.com", value: "TEST_OWNERSHIP_VALUE" }] });
        return route.fulfill({ status: 201, json: sites[0] });
      }
      if (path.endsWith("/history")) return route.fulfill({ json: { items: [{ version: 1, policy: { mode: "observe" }, actor: "fixture-admin", reason: "Test initial configuration", created_at: Date.now() / 1000 }] } });
      if (request.method() === "GET") return route.fulfill({ json: { items: sites } });
      return route.fulfill({ json: sites[0] });
    });
    await page.goto(base + "/ui/#gateway");
    // Boot resolves authentication before it renders. Do not race its final navigation.
    await page.locator("#gwCreate").waitFor({ timeout: 60000 });
    await page.evaluate(async () => { S.ctx = { ...S.ctx, actor_role: "admin" }; S.role = ""; await go("gateway"); });
    await page.locator("#gwCreate [name=website]").fill("https://fixture.customer.com");
    await page.locator("#gwCreate [name=origin]").fill("https://origin.customer.com");
    await page.locator("#gwCreate button").click();
    await page.locator("#gwPolicy").waitFor();
    assert.equal(writes.length, 1);
    assert.match(await page.locator(".gw-coverage").first().innerText(), /unknown/);
    assert.ok(!(await page.locator(".gatewayWorkspace").innerText()).includes("Filtering active"));
    page.once("dialog", dialog => dialog.dismiss());
    await page.locator('[data-gw="rollback"]').click();
    assert.equal(writes.length, 1, "Cancel must not publish a rollback");
    page.once("dialog", dialog => dialog.dismiss());
    await page.locator('[data-gw="bootstrap"]').click();
    assert.equal(writes.length, 1, "Cancel must not rotate credentials");
    for (const width of [320, 390, 768, 1440]) {
      await page.setViewportSize({ width, height: 950 });
      if (!(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1))) {
        console.log(await page.locator(".gatewayWorkspace").evaluate(root => [...root.querySelectorAll("*")].filter(el => {
          const b = el.getBoundingClientRect(); return b.width && b.right > innerWidth + 1 && !el.closest(".gw-table");
        }).map(el => ({ tag: el.tagName, cls: el.className, width: el.getBoundingClientRect().width })).slice(0, 20)));
      }
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), `No overflow at ${width}`);
      if (process.env.PQC_GATEWAY_SCREENSHOTS) {
        require("node:fs").mkdirSync(process.env.PQC_GATEWAY_SCREENSHOTS, { recursive: true });
        await page.evaluate(() => scrollTo(0, 0));
        await page.screenshot({ path: require("node:path").join(process.env.PQC_GATEWAY_SCREENSHOTS, `gateway-${width}.png`) });
      }
    }
    sites[0].runtime = { checked_at: Date.now() / 1000 - 301 };
    sites[0].ownership_verified_at = Date.now() / 1000 - 86401;
    sites[0].coverage = { ...sites[0].coverage, ownership: "verified", filtering: "observe" };
    sites[0].statistics = { requests: 7, matched: 0, blocked: 0, upstream_errors: 0, rule_counts: {}, checked_at: Date.now() / 1000 - 301, scope: "Expired browser fixture" };
    await page.evaluate(() => go("gateway"));
    assert.equal(await page.locator('[data-coverage="filtering"]').innerText(), "unknown");
    assert.equal(await page.locator('[data-coverage="ownership"]').innerText(), "verification required");
    assert.equal(await page.locator("#gwObservations dd").first().innerText(), "Expired");
    await page.evaluate(async () => { S.ctx = { ...S.ctx, actor_role: "viewer" }; await go("gateway"); });
    assert.equal(await page.locator("#gwCreate button").isDisabled(), true);
    assert.equal(await page.locator('[data-gw="apply"]').isDisabled(), true);
    assert.equal(await page.locator('[data-gw="probe"]').isDisabled(), true);
    failed = true;
    await page.evaluate(() => go("gateway"));
    await page.getByRole("alert").filter({ hasText: "Gateway data unavailable" }).waitFor();
    assert.deepEqual(errors, []);
    console.log("PASS: gateway workspace wiring, honest pending states, cancellation, viewer controls, failure states, and responsive layout.");
  } finally { await browser.close(); }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
