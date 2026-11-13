// Motion only when something real happens.
//
// Replaces fabric-smoke.js, which checked the generative background ("the fabric") on every
// surface: that it could be paused and that losing WebGL degraded quietly. The fabric, the 3D
// scenes and the looping panels were removed. This checks the promise that replaced them, on the
// same surfaces: once a page has loaded and settled, nothing on it moves on its own.
//   - no running animation that repeats forever (CSS or Web Animations);
//   - no element left over from the old scenes (.bgfx, .page-fabric, the scene canvases);
//   - no requestAnimationFrame loop: frames requested over two idle seconds stay near zero.
const { chromium } = require("../.tools/video/node_modules/playwright");
const assert = require("node:assert/strict");
const base = (process.env.MORROW_E2E_BASE_URL || "http://127.0.0.1:8001").replace(/\/$/, "");

const SURFACES = ["/", "/league", "/estate", "/algorithms", "/trust", "/ui/#overview", "/security", "/pricing", "/terms",
  "/vendor-admin/", "/vendor-admin/traffic.html"];

async function main() {
  const browser = await chromium.launch({ headless: true });
  const errors = [];
  try {
    const context = await browser.newContext({ viewport: { width: 1280, height: 860 } });
    await context.addInitScript(() => {
      window.__frames = 0;
      const raf = window.requestAnimationFrame.bind(window);
      window.requestAnimationFrame = (cb) => { window.__frames++; return raf(cb); };
    });
    const page = await context.newPage();
    page.on("pageerror", (e) => errors.push(String(e)));
    for (const path of SURFACES) {
      await page.goto(base + path, { waitUntil: "networkidle" });
      await page.waitForTimeout(1500);
      const leftovers = await page.locator(".bgfx, .page-fabric, #signalScene, canvas[data-state]").count();
      assert.equal(leftovers, 0, `${path} still mounts a decorative scene`);
      const looping = await page.evaluate(() => document.getAnimations()
        .filter((a) => a.playState === "running" && a.effect && a.effect.getComputedTiming().iterations === Infinity)
        .map((a) => (a.effect.target && (a.effect.target.className || a.effect.target.tagName)) || "?"));
      assert.deepEqual(looping, [], `${path} has animations that never end`);
      const before = await page.evaluate(() => window.__frames);
      await page.waitForTimeout(2000);
      const frames = (await page.evaluate(() => window.__frames)) - before;
      assert.ok(frames <= 5, `${path} requested ${frames} animation frames while idle`);
    }
    assert.deepEqual(errors, [], "JavaScript errors");
    console.log(`PASS: ${SURFACES.length} surfaces settle: no endless animation, no scene, no idle frame loop.`);
  } finally {
    await browser.close();
  }
}

main().catch((error) => { console.error(error); process.exit(1); });
