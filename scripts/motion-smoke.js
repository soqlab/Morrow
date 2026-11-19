// Motion only when something real happens.
//
// Replaces fabric-smoke.js, which checked the generative background ("the fabric") on every
// surface: that it could be paused and that losing WebGL degraded quietly. The fabric, the 3D
// scenes and the looping panels were removed. This checks the promise that replaced them, on the
// same surfaces: once a page has loaded and settled, nothing on it moves on its own.
//   - no running animation that repeats forever (CSS or Web Animations), with one deliberate
//     exception: the front page's story may run exactly two named animations, hs-breathe (the
//     hero's glow) and hs-marquee (the two rows of names), and only while they are on screen.
//     They are what makes the page feel alive, so they are allowed; they are gated so that an idle
//     page off screen, a hovered or focused row, and reduced motion all stay still (checked below);
//   - the hero's shine runs a counted number of times and stops;
//   - no element left over from the old scenes (.bgfx, .page-fabric, the scene canvases);
//   - no requestAnimationFrame loop: frames requested over two idle seconds stay near zero.
const { chromium } = require("../.tools/video/node_modules/playwright");
const assert = require("node:assert/strict");
const base = (process.env.MORROW_E2E_BASE_URL || "http://127.0.0.1:8001").replace(/\/$/, "");

// The record and proof addresses answer 404 on a server with no data; their pages still wear the
// shared frame and feel (services/site_chrome.py), which is what is checked here.
const SURFACES = ["/", "/league", "/changes", "/report", "/vendors", "/estate", "/algorithms", "/trust", "/ui/#overview", "/security", "/legal", "/terms", "/abuse",
  "/r/motion-smoke.example", "/r/motion-smoke.example/proof",
  "/vendor-admin/", "/vendor-admin/traffic.html"];

/** The front page's two allowed ambient animations (static/home-story.css). Nothing else may repeat. */
const AMBIENT = { "/": ["hs-breathe", "hs-marquee"] };

/** Running animations that never end, with their name and whether their element is on screen. */
function endless(page) {
  return page.evaluate(() => document.getAnimations()
    .filter((a) => a.playState === "running" && a.effect && a.effect.getComputedTiming().iterations === Infinity)
    .map((a) => {
      // A moving row's second copy is off to the side by design: the row, not the copy, is what is on screen.
      const el = a.effect.target, box = el && el.closest ? el.closest(".hs-row") || el : el;
      const r = box && box.getBoundingClientRect ? box.getBoundingClientRect() : null;
      const onScreen = !!r && r.bottom > 0 && r.top < window.innerHeight;
      return { name: a.animationName || "?", target: (el && (el.className || el.tagName)) || "?", onScreen };
    }));
}

function names(tone) {
  const entries = [];
  for (let i = 0; i < 12; i++) {
    entries.push({ domain: tone + "-" + i + ".example", grade: tone === "ok" ? "A" : "C", checked_at: new Date().toISOString(),
      key_exchange: tone === "ok" ? "X25519MLKEM768" : "x25519", sector: "s", sector_name: "S" });
  }
  return { title: "t", kind: tone === "ok" ? "ready" : "not_ready", count: 40, matched: 12, methodology: {}, entries };
}

function playStates(page, row) {
  return page.evaluate((id) => Array.prototype.map.call(document.querySelectorAll("#" + id + " .hs-track"), (t) => getComputedStyle(t).animationPlayState), row);
}

async function frontPage(browser) {
  // Names are supplied here so the rows exist on a server with no data.
  const route = async (ctx) => {
    await ctx.route(/\/api\/public\/checked-safe\?/, (r) => r.fulfill({ json: names("ok") }));
    await ctx.route(/\/api\/public\/not-ready\?/, (r) => r.fulfill({ json: names("warn") }));
  };
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 860 } });
  await route(ctx);
  const page = await ctx.newPage();
  await page.goto(base + "/", { waitUntil: "networkidle" });
  await page.locator("#hs-row-ok .hs-pill").first().waitFor();
  // The hero's shine sweeps a counted number of times, then stops.
  const shine = await page.evaluate(() => document.getAnimations().filter((a) => /hs-shine/.test(a.animationName)).map((a) => a.effect.getComputedTiming().iterations));
  assert.ok(shine.length && shine.every((n) => n === 3), "the shine must run 3 times, not " + shine);
  // On the hero only the glow may run; the rows below it are paused.
  let running = await endless(page);
  assert.deepEqual([...new Set(running.map((a) => a.name))], ["hs-breathe"], "on the hero: " + JSON.stringify(running));
  // The rows run while they are on screen ...
  await page.evaluate(() => document.getElementById("hs-row-ok").scrollIntoView({ block: "center", behavior: "instant" }));
  await page.waitForTimeout(700);
  running = await endless(page);
  assert.ok(running.filter((a) => a.name === "hs-marquee").length >= 2, "the rows do not move on screen: " + JSON.stringify(running));
  assert.ok(running.every((a) => AMBIENT["/"].includes(a.name) && a.onScreen), "off-screen or unnamed animation: " + JSON.stringify(running));
  // ... stop under the pointer and under keyboard focus ...
  await page.hover("#hs-row-ok .hs-track:first-child li:nth-child(2) .hs-pill", { force: true });
  await page.waitForTimeout(200);
  assert.deepEqual(await playStates(page, "hs-row-ok"), ["paused", "paused"], "the row keeps moving under the pointer");
  await page.mouse.move(2, 2);
  await page.focus("#hs-row-no .hs-track:first-child .hs-pill");
  await page.waitForTimeout(200);
  assert.deepEqual(await playStates(page, "hs-row-no"), ["paused", "paused"], "the row keeps moving under keyboard focus");
  assert.equal(await page.locator('#hs-row-no .hs-track[aria-hidden="true"]').getAttribute("inert"), "", "the moving copy must be inert");
  // ... and stop off screen.
  await page.evaluate(() => document.activeElement && document.activeElement.blur());
  await page.evaluate(() => document.getElementById("hs-board").scrollIntoView({ behavior: "instant" }));
  await page.waitForTimeout(700);
  running = await endless(page);
  assert.deepEqual(running, [], "animations run off screen: " + JSON.stringify(running));
  await ctx.close();

  // Reduced motion: nothing moves at all, and the rows are lists that scroll sideways.
  const still = await browser.newContext({ viewport: { width: 390, height: 844 }, reducedMotion: "reduce" });
  await route(still);
  const calm = await still.newPage();
  await calm.goto(base + "/", { waitUntil: "networkidle" });
  await calm.locator("#hs-row-ok .hs-pill").first().waitFor();
  await calm.evaluate(() => document.getElementById("hs-row-ok").scrollIntoView({ block: "center", behavior: "instant" }));
  await calm.waitForTimeout(400);
  const moving = await calm.evaluate(() => document.getAnimations().filter((a) => a.playState === "running").map((a) => a.animationName || "?"));
  assert.deepEqual(moving, [], "reduced motion still animates: " + moving);
  assert.equal(await calm.evaluate(() => getComputedStyle(document.getElementById("hs-row-ok")).overflowX), "auto", "the rows must scroll under reduced motion");
  assert.equal(await calm.evaluate(() => getComputedStyle(document.querySelector('#hs-row-ok .hs-track[aria-hidden="true"]')).display), "none");
  assert.ok(await calm.evaluate(() => { const r = document.getElementById("hs-row-ok"); return r.scrollWidth > r.clientWidth; }), "the row cannot be scrolled");
  await still.close();
}

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
      const looping = (await endless(page)).filter((a) => !((AMBIENT[path] || []).includes(a.name) && a.onScreen));
      assert.deepEqual(looping, [], `${path} has animations that never end`);
      const before = await page.evaluate(() => window.__frames);
      await page.waitForTimeout(2000);
      const frames = (await page.evaluate(() => window.__frames)) - before;
      assert.ok(frames <= 5, `${path} requested ${frames} animation frames while idle`);
    }
    await frontPage(browser);
    assert.deepEqual(errors, [], "JavaScript errors");
    console.log(`PASS: ${SURFACES.length} surfaces settle: no endless animation, no scene, no idle frame loop; the front page's two named animations run only on screen, pause on hover and focus, and stop under reduced motion.`);
  } finally {
    await browser.close();
  }
}

main().catch((error) => { console.error(error); process.exit(1); });
