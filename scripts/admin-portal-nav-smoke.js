// Operator console navigation smoke: every dropdown item reaches a rendered page, menus work from
// the keyboard, the Ctrl+K palette finds a page and an organization, the notifications panel
// opens, Customer 360 opens from the organization list, the range picker drives the dashboard
// request, and the phone drawer works without horizontal overflow. Read-only: nothing is created.
const { chromium } = require("../.tools/video/node_modules/playwright");
const assert = require("node:assert/strict");
const base = (process.env.MORROW_E2E_BASE_URL || "http://127.0.0.1:8001").replace(/\/$/, "");
const key = process.env.MORROW_E2E_PLATFORM_KEY;
if (!key) throw new Error("MORROW_E2E_PLATFORM_KEY is required for the portal navigation smoke.");

const PAGE_FOR_ROUTE = { "customer-360": "customer360" };
const hashOf = page => page.evaluate(() => location.hash);

async function main() {
  let browser;
  try { browser = await chromium.launch({ headless: true }); }
  catch { browser = await chromium.launch({ headless: true, channel: "chrome" }); }
  try {
    const context = await browser.newContext({ viewport: { width: 1440, height: 950 }, reducedMotion: "reduce" });
    const page = await context.newPage();
    const errors = [];
    page.on("pageerror", error => errors.push(error.message));

    // Sign-in is its own screen until a credential connects.
    await page.goto(base + "/vendor-admin/");
    assert.equal(await page.locator("#signinScreen").isVisible(), true, "sign-in screen shows first");
    assert.equal(await page.locator("#appShell").isVisible(), false, "app shell waits for a credential");
    await page.locator("#platformKey").fill(key);
    await page.locator("#loadBtn").click();
    await page.waitForFunction(() => document.querySelector("#apiState").textContent === "API connected", null, { timeout: 60000 });
    assert.equal(await page.locator("#signinScreen").isVisible(), false, "sign-in screen gives way to the shell");
    assert.equal(await hashOf(page), "#/dashboard");
    console.log("Sign-in screen and shell hand-off passed.");

    // Every dropdown item routes somewhere real.
    const ia = await page.evaluate(() => window.AdminShell.IA.map(g => ({ id: g.id, route: g.route, items: (g.items || []).map(i => ({ route: i.route, label: i.label, url: i.url || "", external: !!i.external })) })));
    let pages = 0;
    for (const group of ia) {
      if (!group.items.length) continue;
      for (const item of group.items) {
        const link = page.locator(`.sh-link[data-route="${item.route}"]`);
        if (item.url) {
          assert.equal(await link.getAttribute("href"), item.url, `${item.label} links to ${item.url}`);
          assert.equal((await context.request.get(base + item.url)).status(), 200, `${item.label} destination answers`);
          continue;
        }
        await page.locator(`.sh-top[data-top="${group.id}"]`).click();
        await link.waitFor({ state: "visible" });
        await link.click();
        const pageKey = PAGE_FOR_ROUTE[item.route] || item.route;
        await page.locator(`[data-page="${pageKey}"]`).waitFor({ state: "visible" });
        assert.equal(await hashOf(page), `#/${item.route}`, `${item.label} sets its hash route`);
        assert.equal(await page.locator(`.sh-link[data-route="${item.route}"]`).getAttribute("aria-current"), "page", `${item.label} is marked current`);
        assert.ok((await page.locator(`.sh-top[data-top="${group.id}"]`).getAttribute("class")).includes("sh-current"), `${group.id} section is highlighted`);
        await page.waitForTimeout(1500);
        const visibleErrors = await page.locator(`[data-page="${pageKey}"] .errorState:visible`).allInnerTexts();
        assert.deepEqual(visibleErrors, [], `${item.label} renders without an error state`);
        const text = (await page.locator(`[data-page="${pageKey}"]`).innerText()).trim();
        assert.ok(text.length > 20, `${item.label} renders content`);
        pages++;
      }
    }
    assert.ok(pages >= 20, `expected at least 20 in-app pages, visited ${pages}`);
    // Traffic Lens is its own page with the same top bar.
    const traffic = await context.newPage();
    traffic.on("pageerror", error => errors.push("traffic: " + error.message));
    await traffic.goto(base + "/vendor-admin/traffic.html");
    assert.ok((await traffic.locator(".sh-bar .sh-top").count()) >= 7, "Traffic Lens carries the console menus");
    assert.equal(await traffic.locator('.sh-link[data-route="users"]').getAttribute("href"), "/vendor-admin/#/users");
    await traffic.close();
    console.log(`Every dropdown item routes to a rendered page (${pages} in-app pages).`);

    // Back and forward restore routes.
    await page.goBack();
    await page.waitForFunction(() => location.hash !== "#/customer-360");
    await page.goForward();
    await page.waitForFunction(() => location.hash === "#/customer-360" || location.hash === "#/data");
    console.log("Back/forward navigation passed.");

    // Keyboard navigation of the menus.
    await page.evaluate(() => { location.hash = "#/dashboard"; });
    await page.locator('[data-page="dashboard"]').waitFor();
    await page.locator('.sh-top[data-top="customers"]').focus();
    await page.keyboard.press("ArrowDown");
    assert.equal(await page.locator('.sh-top[data-top="customers"]').getAttribute("aria-expanded"), "true");
    assert.equal(await page.evaluate(() => document.activeElement.dataset.route), "customers");
    await page.keyboard.press("ArrowDown");
    assert.equal(await page.evaluate(() => document.activeElement.dataset.route), "customer-360");
    await page.keyboard.press("ArrowUp");
    assert.equal(await page.evaluate(() => document.activeElement.dataset.route), "customers");
    // Menu order comes from the page, so adding a menu or an item does not break the keyboard checks.
    const order = await page.evaluate(() => {
      const tops = [...document.querySelectorAll(".sh-top[data-top]")].map(t => t.dataset.top);
      const itemsOf = id => [...document.querySelectorAll(`#shDrop-${id} [data-route]`)].map(a => a.dataset.route);
      const next = tops[tops.indexOf("customers") + 1];
      return { lastCustomers: itemsOf("customers").pop(), next, nextIsMenu: !!document.querySelector(`#shDrop-${next}`), nextFirst: itemsOf(next)[0] };
    });
    await page.keyboard.press("End");
    assert.equal(await page.evaluate(() => document.activeElement.dataset.route), order.lastCustomers);
    await page.keyboard.press("Escape");
    assert.equal(await page.locator('.sh-top[data-top="customers"]').getAttribute("aria-expanded"), "false");
    assert.equal(await page.evaluate(() => document.activeElement.dataset.top), "customers", "Escape returns focus to the menu button");
    await page.keyboard.press("ArrowRight");
    assert.equal(await page.evaluate(() => document.activeElement.dataset.top), order.next);
    if (order.nextIsMenu && order.nextFirst) {
      await page.keyboard.press("Enter");
      assert.equal(await page.locator(`.sh-top[data-top="${order.next}"]`).getAttribute("aria-expanded"), "true");
      await page.keyboard.press("ArrowDown");
      assert.equal(await page.evaluate(() => document.activeElement.dataset.route), order.nextFirst);
      await page.keyboard.press("Enter");
      await page.waitForFunction(route => location.hash === `#/${route}`, order.nextFirst);
      assert.equal(await page.locator(`#shDrop-${order.next}`).isVisible(), false, "choosing an item closes the menu");
    }
    // Outside click closes an open menu.
    await page.locator('.sh-top[data-top="security"]').click();
    assert.equal(await page.locator("#shDrop-security").isVisible(), true);
    await page.mouse.click(700, 600);
    assert.equal(await page.locator("#shDrop-security").isVisible(), false, "outside click closes the menu");
    console.log("Menu keyboard navigation, Escape and outside click passed.");

    // Ctrl+K finds a page and an organization.
    await page.keyboard.press("Control+K");
    await page.locator(".sh-palette input").waitFor({ state: "visible" });
    await page.keyboard.type("audit log");
    await page.locator('.sh-palItem[aria-selected="true"]', { hasText: "Audit log" }).waitFor();
    await page.keyboard.press("Enter");
    await page.waitForFunction(() => location.hash === "#/audit");
    const org = await page.evaluate(() => window.AirlockAdmin.customers()[0]);
    if (org) {
      const query = String(org.name || org.organization_id).slice(0, 6);
      await page.keyboard.press("Control+K");
      await page.locator(".sh-palette input").waitFor({ state: "visible" });
      await page.keyboard.type(query);
      const option = page.locator(".sh-palItem", { hasText: org.name || org.organization_id }).first();
      await option.waitFor({ timeout: 15000 }).catch(async error => {
        console.error("Palette shows:", await page.locator(".sh-palette").isVisible(), await page.locator(".sh-palList").innerText().catch(() => ""), await page.locator(".sh-palette input").inputValue().catch(() => ""));
        throw error;
      });
      await option.click();
      await page.waitForFunction(id => location.hash === `#/customers/${encodeURIComponent(id)}`, org.organization_id);
      await page.locator("#c360").waitFor({ state: "visible" });
    }
    console.log("Command palette found a page and an organization.");

    // Notifications panel.
    await page.locator("#shBellBtn").click();
    await page.locator("#shBellPanel").waitFor({ state: "visible" });
    await page.waitForFunction(() => !/Loading notifications/.test(document.querySelector("[data-bell-body]").textContent));
    assert.ok((await page.locator("[data-bell-body]").innerText()).trim().length > 0, "notifications panel renders");
    await page.keyboard.press("Escape");
    assert.equal(await page.locator("#shBellPanel").isVisible(), false);
    console.log("Notifications panel passed.");

    // Customer 360 from the organization list.
    await page.evaluate(() => { location.hash = "#/customers"; });
    const row = page.locator("#customersBody .customerRow").first();
    if (await row.count()) {
      const orgId = await row.getAttribute("data-org");
      await row.click();
      await page.waitForFunction(id => location.hash === `#/customers/${encodeURIComponent(id)}`, orgId);
      await page.waitForFunction(id => document.querySelector("#c360OrgId").textContent === id && !document.querySelector("#c360Kpis .skel"), orgId, { timeout: 30000 });
      assert.ok((await page.locator("#c360Name").innerText()).trim().length > 0);
      assert.deepEqual(await page.locator('[data-page="customer360"] .errorState:visible').allInnerTexts(), []);
      assert.ok((await page.locator("#crumbs").innerText()).toUpperCase().includes("ORGANIZATIONS"), "breadcrumb shows the path to the customer");
      console.log("Customer 360 opened from the organization list.");
    }

    // The range picker changes the dashboard request, and the choice is kept for the tab.
    await page.evaluate(() => { location.hash = "#/dashboard"; });
    await page.locator('[data-page="dashboard"]').waitFor();
    const ranged = page.waitForRequest(request => request.url().includes("/platform/analytics/overview?range=30d"));
    await page.locator('#rangePicker [data-range="30d"]').click();
    await ranged;
    assert.equal(await page.locator('#rangePicker [data-range="30d"]').getAttribute("aria-checked"), "true");
    assert.equal(await page.evaluate(() => sessionStorage.getItem("morrow_admin_range")), "30d");
    console.log("Range picker drives the analytics request.");

    // Phone drawer.
    await page.setViewportSize({ width: 390, height: 844 });
    await page.waitForTimeout(400);
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, "no horizontal overflow at 390px");
    assert.equal(await page.locator(".sh-search span").isVisible(), false);
    await page.locator("[data-shell-burger]").click();
    assert.equal(await page.locator("[data-shell-burger]").getAttribute("aria-expanded"), "true");
    const box = await page.locator("#shellNav").boundingBox();
    assert.ok(box && box.x >= 0 && box.width <= 390, "drawer slides fully on screen");
    const customers = page.locator('.sh-top[data-top="customers"]');
    if ((await customers.getAttribute("aria-expanded")) !== "true") await customers.click();
    await page.locator('.sh-link[data-route="users"]').click();
    await page.waitForFunction(() => location.hash === "#/users");
    assert.equal(await page.locator("[data-shell-burger]").getAttribute("aria-expanded"), "false", "choosing a page closes the drawer");
    await page.waitForTimeout(800);
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, "no overflow after navigating on a phone");
    await page.locator("[data-shell-burger]").click();
    await page.keyboard.press("Escape");
    assert.equal(await page.locator("[data-shell-burger]").getAttribute("aria-expanded"), "false", "Escape closes the drawer");
    console.log("390px drawer passed.");

    assert.deepEqual(errors, [], "Uncaught browser exceptions");
    console.log("Admin portal navigation smoke passed.");
  } finally { await browser.close(); }
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
