const { chromium } = require("../.tools/video/node_modules/playwright");
const assert = require("node:assert/strict");
const base = (process.env.MORROW_E2E_BASE_URL || "http://127.0.0.1:8001").replace(/\/$/, "");

// A panel that has just been re-shown restarts its animation, and Chromium does
// not tick it until the element paints. Sampling before that first tick makes
// "does it animate" read as "no" on a slow frame, so wait for the animation to
// actually start before measuring that it progresses.
async function animationStarted(locator) {
  await locator.evaluate(el => new Promise((resolve, reject) => {
    let frames = 0;
    const check = () => {
      if ((el.getAnimations()[0]?.currentTime || 0) > 0) return resolve();
      if (++frames > 240) return reject(new Error("animation never started"));
      requestAnimationFrame(check);
    };
    check();
  }));
}

async function maxPixelDelta(page, first, second) {
  return page.evaluate(async sources => {
    const pixels = [];
    for (const source of sources) {
      const image = new Image();
      image.src = "data:image/png;base64," + source;
      await image.decode();
      const canvas = document.createElement("canvas");
      canvas.width = image.width;
      canvas.height = image.height;
      const context = canvas.getContext("2d");
      context.drawImage(image, 0, 0);
      pixels.push(context.getImageData(0, 0, canvas.width, canvas.height).data);
    }
    if (pixels[0].length !== pixels[1].length) return 255;
    let maximum = 0;
    for (let i = 0; i < pixels[0].length; i++) maximum = Math.max(maximum, Math.abs(pixels[0][i] - pixels[1][i]));
    return maximum;
  }, [first.toString("base64"), second.toString("base64")]);
}

async function main() {
  let browser;
  try { browser = await chromium.launch({ headless: true }); }
  catch { browser = await chromium.launch({ headless: true, channel: "chrome" }); }
  const errors = [];
  try {
    const context = await browser.newContext({ viewport: { width: 1440, height: 960 } });
    const page = await context.newPage();
    let statusRequests = 0;
    const externalRequests = [];
    page.on("pageerror", error => errors.push(error.message));
    page.on("request", request => {
      if (new URL(request.url()).pathname === "/status") statusRequests++;
      if (new URL(request.url()).origin !== new URL(base).origin) externalRequests.push(request.url());
    });
    await page.goto(base + "/");
    await page.locator("#motionToggle").waitFor({ state: "visible" });
    await page.waitForTimeout(1600);
    assert.equal(statusRequests, 0, "No background polling before the status section is visible");
    const scene = page.locator(".hero-art");
    const first = await scene.screenshot();
    await page.waitForTimeout(600);
    assert.ok(await maxPixelDelta(page, first, await scene.screenshot()) > 10, "Hero artwork must actually move");
    const webgl = await page.evaluate(() => window.airlockScene.available);
    if (webgl) assert.equal(await page.locator("#signalScene").getAttribute("data-state"), "running");
    await page.locator("#motionToggle").click();
    await page.waitForTimeout(200);
    const paused = await scene.screenshot();
    await page.waitForTimeout(450);
    assert.ok(await maxPixelDelta(page, paused, await scene.screenshot()) <= 1, "Pause must freeze the hero");
    assert.equal(await page.locator("#motionToggle").getAttribute("aria-pressed"), "true");
    let previousMode = paused;
    for (const [index, chapter] of ["protect", "prove", "discover"].entries()) {
      await page.locator(`[data-fabric-mode="${chapter}"]`).click();
      assert.equal(await page.locator(`#panel-${chapter}`).isVisible(), true);
      assert.equal(await page.locator(`#tab-${chapter}`).getAttribute("aria-selected"), "true");
      assert.equal(await page.locator('[data-fabric-mode][aria-pressed="true"]').count(), 1);
      assert.equal(await page.locator("#fabricIndex").innerText(), ["02", "03", "01"][index]);
      const modeFrame = await scene.screenshot();
      assert.ok(await maxPixelDelta(page, modeFrame, previousMode) > 10, "Each fabric mode changes the actual artwork, even while paused");
      await page.waitForTimeout(200);
      assert.ok(await maxPixelDelta(page, modeFrame, await scene.screenshot()) <= 1, "Mode selection must not resume paused motion");
      if (webgl) assert.equal(await page.locator("#signalScene").getAttribute("data-state"), "paused");
      previousMode = modeFrame;
    }
    if (webgl) {
      const pixels = await page.locator("#signalScene").evaluate(canvas => canvas.width * canvas.height);
      assert.ok(pixels <= 1002000, "Renderer has a bounded pixel budget");
      const loss = await page.evaluateHandle(() => document.querySelector("#signalScene").getContext("webgl").getExtension("WEBGL_lose_context"));
      if (await loss.evaluate(extension => Boolean(extension))) {
        await loss.evaluate(extension => extension.loseContext());
        await page.waitForFunction(() => document.querySelector("#signalScene").dataset.state === "unavailable");
        assert.equal(await scene.evaluate(el => el.classList.contains("scene-ready")), false);
        await page.waitForTimeout(250);
        await loss.evaluate(extension => extension.restoreContext());
        await page.waitForFunction(() => window.airlockScene.available);
        assert.equal(await page.locator("#signalScene").getAttribute("data-state"), "paused", "Context recovery preserves the user's pause preference");
      }
      await loss.dispose();
    }
    const geometry = await page.evaluate(() => ({
      hero: document.querySelector(".hero").getBoundingClientRect().height,
      claimBottom: document.querySelector("#platform h2").getBoundingClientRect().bottom,
      total: document.documentElement.scrollHeight,
    }));
    assert.ok(geometry.hero <= 680, "Desktop hero must not consume an oversized full screen");
    assert.ok(geometry.claimBottom <= 960, "Core claim fits in the first desktop viewport");
    assert.ok(geometry.total < 3800, "Public page keeps a compact desktop layout");
    await page.reload();
    assert.equal(await page.locator("#motionLabel").innerText(), "Play motion", "Explicit preference persists");
    await page.locator("#motionToggle").click();

    await page.locator("#menuToggle").click();
    assert.equal(await page.locator("#siteMenu").isVisible(), true);
    await page.keyboard.press("Escape");
    assert.equal(await page.locator("#siteMenu").isVisible(), false);
    assert.equal(await page.locator("#menuToggle").evaluate(el => el === document.activeElement), true);

    // Pin the chapter to the viewport top; the compact layout can otherwise leave the hero visible.
    await page.locator(".platform-stage").evaluate(el => el.scrollIntoView({ block: "start", behavior: "instant" }));
    await page.locator("#tab-discover").focus();
    await page.keyboard.press("ArrowRight");
    assert.equal(await page.locator("#panel-protect").isVisible(), true);
    assert.equal(await page.locator("#panel-discover").isVisible(), false);
    assert.equal(await page.locator('[data-fabric-mode="protect"]').getAttribute("aria-pressed"), "true");
    await page.keyboard.press("End");
    assert.equal(await page.locator("#panel-prove").isVisible(), true);
    await page.keyboard.press("Home");
    assert.equal(await page.locator("#panel-discover").isVisible(), true);
    if (webgl) await page.waitForFunction(() => document.querySelector("#signalScene").dataset.state === "paused");
    const flow = page.locator("#panel-discover .diagram-flow");
    await animationStarted(flow);
    const offset = await flow.evaluate(el => getComputedStyle(el).strokeDashoffset);
    await page.waitForTimeout(200);
    assert.notEqual(await flow.evaluate(el => getComputedStyle(el).strokeDashoffset), offset, "Architecture flow animates");

    await page.locator(".boundary-fabric").scrollIntoViewIfNeeded();
    const boundaryFlow = page.locator(".boundary-pulses path").first();
    await animationStarted(boundaryFlow);
    const boundaryOffset = await boundaryFlow.evaluate(el => getComputedStyle(el).strokeDashoffset);
    await page.waitForTimeout(250);
    assert.notEqual(await boundaryFlow.evaluate(el => getComputedStyle(el).strokeDashoffset), boundaryOffset, "Boundary fabric actually flows");
    await page.evaluate(() => document.querySelector("#motionToggle").click());
    const boundaryPaused = await boundaryFlow.evaluate(el => getComputedStyle(el).strokeDashoffset);
    await page.waitForTimeout(250);
    assert.equal(await boundaryFlow.evaluate(el => getComputedStyle(el).strokeDashoffset), boundaryPaused, "Global pause freezes the second fabric too");
    await page.evaluate(() => document.querySelector("#motionToggle").click());

    const links = await page.locator('a[href^="/"]').evaluateAll(nodes =>
      [...new Set(nodes.map(node => node.getAttribute("href").split("#")[0]))]);
    for (const link of links) assert.equal((await context.request.get(base + link)).status(), 200, link);
    const live = await context.request.get(base + "/status");
    const expected = (await live.json()).status;
    await page.locator("#serviceStatus").scrollIntoViewIfNeeded();
    await page.waitForFunction(() => document.querySelector("#serviceStatus").dataset.state !== "pending");
    assert.equal(await page.locator("#serviceStatus").getAttribute("data-state"), expected);
    assert.equal(statusRequests, 1, "One on-demand public status request");
    assert.deepEqual(externalRequests, [], "No third-party media, fonts, analytics, or requests");
    assert.equal(await boundaryFlow.evaluate(el => getComputedStyle(el).animationPlayState), "paused", "Offscreen boundary fabric suspends");
    console.log("PASS: woven motion, modes, context recovery, density, pixel budget, global pause, offscreen suspension, navigation, links, real status.");

    await page.emulateMedia({ reducedMotion: "reduce" });
    await page.goto(base + "/");
    assert.equal(await page.locator("#motionToggle").isDisabled(), true);
    assert.equal(await page.locator("#motionLabel").innerText(), "Reduced motion");
    const reduced = await scene.screenshot();
    await page.waitForTimeout(300);
    assert.ok(await maxPixelDelta(page, reduced, await scene.screenshot()) <= 1, "Reduced motion holds a static frame");
    await page.locator('[data-fabric-mode="prove"]').click();
    assert.equal(await page.locator("#panel-prove").isVisible(), true);
    assert.ok(await maxPixelDelta(page, reduced, await scene.screenshot()) > 10, "Reduced-motion users can still change the fabric's static mode");
    await page.locator("#tab-prove").click();
    assert.equal(await page.locator("#panel-prove .chapter-copy").evaluate(el => getComputedStyle(el).opacity), "1");

    for (const width of [320, 390, 768, 1440]) {
      await page.setViewportSize({ width, height: 900 });
      for (const chapter of ["discover", "protect", "prove"]) {
        await page.locator("#tab-" + chapter).click();
        const widths = await page.evaluate(() => [innerWidth, document.documentElement.scrollWidth]);
        assert.ok(widths[1] <= widths[0] + 1, "No overflow at " + width + " in " + chapter);
      }
      await page.locator("#menuToggle").click();
      assert.equal(await page.locator("#siteMenu").isVisible(), true);
      await page.keyboard.press("Escape");
    }
    console.log("PASS: reduced motion, visible paused content, mobile/tablet/desktop layout.");

    const healthContext = await browser.newContext({ reducedMotion: "reduce" });
    const health = await healthContext.newPage();
    health.on("pageerror", error => errors.push(error.message));
    await health.clock.install();
    let mode = "healthy", calls = 0, delayedRoute;
    let releaseDelayed, notifySlowStarted;
    await health.route("**/status", async route => {
      calls++;
      if (mode === "network") return route.abort("failed");
      if (mode === "slow") {
        delayedRoute = route;
        const released = new Promise(resolve => { releaseDelayed = resolve; });
        notifySlowStarted();
        await released;
      }
      const now = await health.evaluate(() => Date.now());
      const data = {
        status: mode === "degraded" ? "degraded" : "operational",
        generated_at: new Date(now - (mode === "stale" ? 180000 : 0)).toISOString(),
        checks: { api: { status: "ok" }, database: { status: mode === "degraded" ? "degraded" : "ok" } }
      };
      if (mode === "invalid") delete data.checks;
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(data) }).catch(() => {});
    });
    await health.goto(base + "/");
    await health.locator("#serviceStatus").scrollIntoViewIfNeeded();
    await health.waitForFunction(() => document.querySelector("#serviceStatus").dataset.state === "operational");
    await health.clock.fastForward(59000);
    assert.equal(calls, 1);
    mode = "degraded";
    await health.clock.fastForward(1100);
    await health.waitForFunction(() => document.querySelector("#serviceStatus").dataset.state === "degraded");
    for (const state of ["invalid", "stale", "network"]) {
      mode = state;
      const before = calls;
      await health.clock.fastForward(60100);
      await health.waitForFunction(() => document.querySelector("#serviceStatus").dataset.state === "unavailable");
      assert.equal(calls, before + 1, state + " produces a real refresh and no healthy badge");
      await health.waitForTimeout(80);
    }
    mode = "slow";
    const slowStarted = new Promise(resolve => { notifySlowStarted = resolve; });
    await health.clock.fastForward(60100);
    await Promise.race([slowStarted, new Promise((_, reject) => setTimeout(() => reject(new Error("Slow status request did not start")), 5000))]);
    assert.ok(delayedRoute, "Slow request started");
    await health.clock.fastForward(8100);
    await health.waitForFunction(() => document.querySelector("#serviceStatus").dataset.state === "unavailable");
    releaseDelayed();
    await health.locator("#platform").scrollIntoViewIfNeeded();
    const offscreenCalls = calls;
    await health.clock.fastForward(121000);
    assert.equal(calls, offscreenCalls, "No status polling when offscreen");
    mode = "healthy";
    await health.locator("#serviceStatus").scrollIntoViewIfNeeded();
    await health.waitForFunction(() => document.querySelector("#serviceStatus").dataset.state === "operational");
    console.log("PASS: polling cadence, degraded/malformed/stale/offline/timeout states, offscreen pause, recovery.");
    await healthContext.close();

    const fallbackContext = await browser.newContext({ viewport: { width: 1440, height: 960 } });
    const fallback = await fallbackContext.newPage();
    await fallback.addInitScript(() => {
      const getContext = HTMLCanvasElement.prototype.getContext;
      HTMLCanvasElement.prototype.getContext = function(type, ...args) {
        return type === "webgl" ? null : getContext.call(this, type, ...args);
      };
    });
    await fallback.goto(base + "/");
    assert.equal(await fallback.locator("#signalScene").getAttribute("data-state"), "unavailable");
    const fallbackArt = fallback.locator(".hero-art");
    await fallback.waitForTimeout(1600);
    const fallbackFrame = await fallbackArt.screenshot();
    await fallback.waitForTimeout(300);
    assert.ok(await maxPixelDelta(fallback, fallbackFrame, await fallbackArt.screenshot()) > 10, "CSS fallback still moves without WebGL");
    await fallback.locator("#motionToggle").click();
    await fallback.waitForTimeout(350);
    const fallbackPaused = await fallbackArt.screenshot();
    const fallbackTimes = await fallback.locator(".scene-fallback span").evaluateAll(nodes => nodes.flatMap(node => node.getAnimations().map(animation => [animation.currentTime, animation.playState])));
    await fallback.waitForTimeout(300);
    // Chromium can dither transformed CSS textures by one RGB level even with a frozen timeline.
    assert.ok(await maxPixelDelta(fallback, fallbackPaused, await fallbackArt.screenshot()) <= 1, "Fallback pause freezes visible geometry");
    assert.deepEqual(await fallback.locator(".scene-fallback span").evaluateAll(nodes => nodes.flatMap(node => node.getAnimations().map(animation => [animation.currentTime, animation.playState]))), fallbackTimes);
    assert.equal(await fallback.locator(".scene-fallback span").evaluateAll(nodes => nodes.every(node => getComputedStyle(node).animationPlayState === "paused")), true);
    await fallback.locator('[data-fabric-mode="protect"]').click();
    assert.ok(await maxPixelDelta(fallback, fallbackPaused, await fallbackArt.screenshot()) > 10, "Fallback mode also changes composition");
    assert.equal(await fallback.locator("#panel-protect").isVisible(), true);
    await fallbackContext.close();

    const noScriptContext = await browser.newContext({ javaScriptEnabled: false, reducedMotion: "reduce" });
    const noScript = await noScriptContext.newPage();
    await noScript.goto(base + "/");
    assert.equal(await noScript.locator("#panel-prove").isVisible(), true);
    assert.equal(await noScript.locator("#platform h2").isVisible(), true);
    assert.equal(await noScript.locator("#motionToggle").isVisible(), false);
    assert.equal(await noScript.locator(".fabric-modes").isVisible(), false);
    assert.ok((await noScript.locator("#serviceLabel").innerText()).includes("not checked"));
    await noScriptContext.close();
    assert.deepEqual(errors, []);
    console.log("PASS: animated no-WebGL fallback, fallback pause, readable no-JavaScript content, no JS errors.");
  } finally { await browser.close(); }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
