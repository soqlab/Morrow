// The live instrument at / and its views, in a real browser.
//
// Replaces landing-motion-smoke.js, which checked the decorative landing scene, its motion toggle
// and its status poll. That page was retired; what is asserted now is the opposite promise:
//   - nothing animates on its own: after load, no running animation anywhere on the page;
//   - every request the page makes goes to this origin;
//   - the one input recognises what is typed (domain, algorithm, CVE, commit) and the address is
//     the interface (/<domain> opens that domain's view);
//   - the technicality dial changes the wording and is kept in the URL;
//   - the plain version works with JavaScript switched off;
//   - no horizontal overflow at phone width; no JavaScript errors.
const { chromium } = require("../.tools/video/node_modules/playwright");
const assert = require("node:assert/strict");
const base = (process.env.MORROW_E2E_BASE_URL || "http://127.0.0.1:8001").replace(/\/$/, "");
const origin = new URL(base).origin;

async function main() {
  const browser = await chromium.launch({ headless: true });
  const errors = [];
  const foreign = [];
  try {
    const context = await browser.newContext({ viewport: { width: 1280, height: 860 } });
    const page = await context.newPage();
    page.on("pageerror", (e) => errors.push(String(e)));
    page.on("request", (r) => { const u = r.url(); if (!u.startsWith(origin) && !u.startsWith("data:")) foreign.push(u); });

    await page.goto(`${base}/`, { waitUntil: "networkidle" });
    await page.locator("#home-q").waitFor();
    await page.waitForFunction(() => document.querySelector("#home-stats .reading, #home-stats .i-empty") !== null, null, { timeout: 30000 });
    const running = await page.evaluate(() => document.getAnimations().filter((a) => a.playState === "running").length);
    assert.equal(running, 0, "something animates on its own after load");
    assert.ok(await page.locator("#i-build").innerText(), "the commit line is empty");

    await page.fill("#home-q", "https://www.Example.com/path");
    await page.locator('.i-opt[data-kind="domain"]').first().waitFor();
    assert.match(await page.locator(".i-opt").first().innerText(), /example\.com/i);
    await page.fill("#home-q", "kyber");
    assert.equal(await page.locator(".i-opt").first().getAttribute("href"), "/algorithms/ml-kem");
    await page.fill("#home-q", "CVE-2014-0160");
    assert.equal(await page.locator(".i-opt").first().getAttribute("data-kind"), "cve");
    await page.fill("#home-q", "deadbeef1");
    assert.equal(await page.locator(".i-opt").first().getAttribute("data-kind"), "commit");

    await page.keyboard.press("Escape");
    await page.locator("body").click();
    await page.keyboard.press("Control+k");
    await page.locator("#pal-q").waitFor();
    await page.keyboard.type("league");
    await page.keyboard.press("Enter");
    await page.waitForURL(`${base}/league`);

    await page.goto(`${base}/algorithms/x25519`, { waitUntil: "networkidle" });
    const standard = await page.locator("#say").innerText();
    await page.locator('#i-dial button[data-d="plain"]').click();
    assert.ok(page.url().includes("depth=plain"), "the dial is not kept in the URL");
    const plain = await page.locator("#say").innerText();
    assert.notEqual(plain, standard, "the dial did not change the wording");

    await page.goto(`${base}/trust`, { waitUntil: "networkidle" });
    await page.locator("#tr-req p").first().waitFor({ timeout: 30000 });
    assert.match(await page.locator("#tr-req").innerText(), /went to/);

    await page.goto(`${base}/wp-login.php`);
    assert.equal(await page.locator("#home-q").count(), 0, "a file path was treated as a domain");

    const phone = await browser.newContext({ viewport: { width: 360, height: 780 } });
    const small = await phone.newPage();
    small.on("pageerror", (e) => errors.push(String(e)));
    for (const path of ["/", "/league", "/algorithms", "/trust", "/atlas"]) {
      await small.goto(`${base}${path}`, { waitUntil: "networkidle" });
      const wide = await small.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
      assert.ok(wide <= 1, `${path} overflows a 360px screen by ${wide}px`);
    }

    const noJs = await browser.newContext({ javaScriptEnabled: false });
    const plainPage = await noJs.newPage();
    const response = await plainPage.goto(`${base}/plain`);
    assert.equal(response.status(), 200);
    assert.ok((await plainPage.content()).includes("Domain to check"), "/plain does not work without JavaScript");
    assert.match(response.headers()["content-security-policy"] || "", /script-src 'none'/);

    assert.deepEqual(foreign, [], "the instrument contacted another origin");
    assert.deepEqual(errors, [], "JavaScript errors");
    console.log("PASS: no ambient motion, this origin only, recognizer, command bar, dial in the URL, trust readout, plain without JS, 360px layout.");
  } finally {
    await browser.close();
  }
}

main().catch((error) => { console.error(error); process.exit(1); });
