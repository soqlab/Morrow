// The generative fabric runs on every surface, including workspaces people keep
// open all day. This checks the properties that make that acceptable: it is
// decorative, it is always stoppable, one pause preference governs the whole
// product, reduced motion wins, and losing WebGL degrades to nothing visible
// rather than to a broken page.
const { chromium } = require("../.tools/video/node_modules/playwright");
const assert = require("node:assert/strict");
const base = (process.env.PQC_E2E_BASE_URL || "http://127.0.0.1:8001").replace(/\/$/, "");

// Every surface that mounts a scene, and the element the canvas lives in.
const SURFACES = [
  ["/ui/", ".bgfx"],
  ["/", ".page-fabric"],
  ["/security", ".page-fabric"],
  ["/pricing", ".page-fabric"],
  ["/vendor-admin/", ".page-fabric"],
  ["/vendor-admin/traffic.html", ".page-fabric"],
];

const sceneState = (page, host) => page.locator(host + " canvas").getAttribute("data-state");

async function launch() {
  const args = ["--use-gl=swiftshader", "--enable-unsafe-swiftshader"];
  try { return await chromium.launch({ headless: true, args }); }
  catch { return chromium.launch({ headless: true, channel: "chrome", args }); }
}

async function main() {
  const browser = await launch();
  const errors = [];
  try {
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });

    // Every surface mounts a scene, and the artwork never reaches for the network.
    const externalRequests = [];
    context.on("request", request => {
      if (new URL(request.url()).origin !== new URL(base).origin) externalRequests.push(request.url());
    });
    for (const [path, host] of SURFACES) {
      const page = await context.newPage();
      page.on("pageerror", error => errors.push(path + ": " + error.message));
      await page.goto(base + path);
      // The landing runs one scene at a time: its page sheet only takes over
      // once the hero has scrolled away.
      if (path === "/") await page.locator("#approach").scrollIntoViewIfNeeded();
      // A context can report itself unavailable for a frame before it settles,
      // so wait for the state itself rather than for any state at all.
      await page.waitForFunction(selector => document.querySelector(selector + " canvas")?.dataset.state === "running", host);
      assert.equal(await page.locator(host).getAttribute("aria-hidden"), "true", path + " hides the artwork from assistive tech");
      assert.equal(await page.locator(host).evaluate(el => getComputedStyle(el).pointerEvents), "none", path + " fabric is inert");
      const budget = await page.locator(host + " canvas").evaluate(c => c.width * c.height);
      assert.ok(budget <= 321000, path + " honours the background pixel budget, got " + budget);
      await page.close();
    }
    assert.deepEqual(externalRequests, [], "The fabric loads no third-party code, fonts, or media");

    // One pause control, one preference, every surface.
    const console_ = await context.newPage();
    console_.on("pageerror", error => errors.push("console: " + error.message));
    await console_.goto(base + "/ui/");
    await console_.waitForFunction(() => document.querySelector(".bgfx canvas")?.dataset.state === "running");
    await console_.locator("[data-motion-toggle]").click();
    assert.equal(await sceneState(console_, ".bgfx"), "paused", "The console control pauses the fabric");
    assert.equal(await console_.locator("[data-motion-toggle]").getAttribute("aria-pressed"), "true");
    await console_.reload();
    await console_.waitForFunction(() => document.querySelector(".bgfx canvas")?.dataset.state === "paused",
      null, { timeout: 15000 });

    const document_ = await context.newPage();
    await document_.goto(base + "/security");
    await document_.waitForFunction(() => document.querySelector(".page-fabric canvas")?.dataset.state === "paused",
      null, { timeout: 15000 });
    // No need to restore the preference: this context is closed here, and every
    // block below opens a fresh one with its own storage.
    await context.close();
    console.log("PASS: fabric mounts on every surface, stays inert and offline, and shares one pause preference.");

    // Reduced motion holds every surface still and offers no control to undo it.
    const reduced = await browser.newContext({ reducedMotion: "reduce", viewport: { width: 1440, height: 900 } });
    for (const [path, host] of SURFACES) {
      const page = await reduced.newPage();
      page.on("pageerror", error => errors.push(path + " (reduced): " + error.message));
      await page.goto(base + path);
      await page.waitForFunction(selector => document.querySelector(selector + " canvas")?.dataset.state === "paused", host);
      assert.equal(await page.evaluate(() => document.body.dataset.motion), "paused", path);
      const toggle = page.locator("[data-motion-toggle]");
      if (await toggle.count()) assert.equal(await toggle.isDisabled(), true, path + " offers no way to force motion on");
      await page.close();
    }
    await reduced.close();

    // No WebGL is a silent absence, not a broken workspace.
    const bare = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    await bare.addInitScript(() => {
      const original = HTMLCanvasElement.prototype.getContext;
      HTMLCanvasElement.prototype.getContext = function (type, ...rest) {
        return type === "webgl" ? null : original.call(this, type, ...rest);
      };
    });
    for (const [path, host, shell] of [["/ui/", ".bgfx", "#app"], ["/security", ".page-fabric", ".doc-shell"]]) {
      const page = await bare.newPage();
      page.on("pageerror", error => errors.push(path + " (no webgl): " + error.message));
      await page.goto(base + path);
      await page.waitForFunction(selector => document.querySelector(selector + " canvas")?.dataset.state === "unavailable", host);
      assert.equal(await page.locator(host).evaluate(el => el.classList.contains("scene-ready")), false, path + " stays unstyled without WebGL");
      assert.equal(await page.locator(shell).isVisible(), true, path + " still renders without WebGL");
      await page.close();
    }
    await bare.close();

    assert.deepEqual(errors, [], "No JavaScript errors on any surface");
    console.log("PASS: reduced motion on every surface, and a graceful no-WebGL fallback.");
  } finally { await browser.close(); }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
