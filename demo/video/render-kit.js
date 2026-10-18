/**
 * The shared rendering kit for both Morrow films.
 *
 * The whole point of this file is the clock. Chrome is driven over CDP with
 * `Emulation.setVirtualTimePolicy`, so the page's idea of time is ours: every
 * captured frame advances it by exactly 1000/60 ms, waits for
 * `Emulation.virtualTimeBudgetExpired`, and only then screenshots. The
 * product's own requestAnimationFrame loops, CSS animations, transitions and
 * timers therefore run at a perfect 16.667 ms a frame no matter how long a
 * frame really took to render — which is what lets the product's motion stay
 * switched *on* without any judder in the result.
 *
 * Frames are captured at a 2x device scale through a fractional clip
 * rectangle, which is also how a push-in is done: Chrome re-rasterises the page
 * at the new scale, so type is drawn at the size it is seen at and a 2 % move
 * over six seconds has no pixel to step on. Frames are piped straight into
 * ffmpeg and downscaled to 1920x1080 with lanczos; nothing hits the disk.
 */
const path = require("path");
const { spawn } = require("child_process");
const { chromium } = require("playwright");

const REPO = path.resolve(__dirname, "..", "..");
const FFMPEG = path.join(REPO, ".tools", "ffmpeg", "ffmpeg.exe");
const BASE = process.env.PQC_DEMO_BASE || "http://127.0.0.1:8049";
const EMAIL = "avery.chen@example.com";
const PASSWORD = "Airlock-Demo-Recording-8049";
const FPS = 60;
const W = 1920, H = 1080;
const FRAME_MS = 1000 / FPS;

/* ------------------------------------------------------------------ browser */
async function open(opts) {
  const o = opts || {};
  const auth = await (await fetch(`${BASE}/auth/login`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: EMAIL, password: PASSWORD }),
  })).json();
  if (!auth.access_token) throw new Error("demo server login failed");

  const browser = await chromium.launch({
    channel: "chrome", headless: true,
    args: ["--disable-background-timer-throttling", "--disable-renderer-backgrounding",
      "--disable-backgrounding-occluded-windows", "--force-color-profile=srgb",
      "--hide-scrollbars", "--font-render-hinting=none", "--disable-lcd-text",
      // Headless Chrome rasterises on SwiftShader by default. Every frame here
      // is a full re-raster of an animating 3840x2160 page, so handing that to
      // the real GPU takes a frame from 400 ms to 290 ms. It changes nothing
      // about what is drawn.
      // PQC_NO_GPU=1 falls back to software rasterisation. It is about twice
      // as slow, and it is the way out when the GPU path stops answering
      // screenshots on a particular page — which the operator workspace does.
      ...(process.env.PQC_NO_GPU
        ? ["--disable-gpu", "--use-gl=swiftshader", "--enable-unsafe-swiftshader"]
        : ["--use-gl=angle", "--use-angle=d3d11", "--enable-gpu", "--ignore-gpu-blocklist"])],
  });
  const ctx = await browser.newContext({
    viewport: { width: W, height: H },
    deviceScaleFactor: 2,
    colorScheme: "dark",
    // No reducedMotion and no paused preference: the product animates.
  });
  await ctx.addInitScript((a) => {
    localStorage.setItem("pqc_token", a.access_token);
    localStorage.setItem("pqc_refresh", a.refresh_token);
    localStorage.setItem("pqc_theme", "dark");
    localStorage.removeItem("airlock-motion-paused");
  }, auth);
  await ctx.addInitScript({ path: path.join(__dirname, "tour-overlay.js") });

  const page = await ctx.newPage();
  page.setDefaultTimeout(20000);
  const external = new Set();
  page.on("request", (r) => {
    const u = r.url();
    if (!u.startsWith(BASE) && !/^(data|blob|about|chrome):/.test(u)) external.add(u);
  });
  page.on("pageerror", (e) => console.log("  PAGEERR", String(e.message).slice(0, 120)));
  // A native dialog blocks the renderer thread, and a blocked renderer answers
  // neither an evaluate nor a screenshot. Nothing in the tour should raise one;
  // this is insurance, and it says so if it ever fires.
  page.on("dialog", (d) => { console.log("  DIALOG", d.type(), d.message().slice(0, 60)); d.dismiss().catch(() => {}); });
  const cdp = await ctx.newCDPSession(page);
  return { browser, ctx, page, cdp, external, auth };
}

/* ----------------------------------------------------------------- watchdog
 * A CDP call that never answers has wedged a render twice: once on a virtual
 * time budget and once on a screenshot, both with the machine idle. Every
 * per-frame call therefore races a timer and is re-sent rather than waited on
 * forever. A re-sent command is harmless — the clock is ours and the page is
 * not being driven by anything else — and if three tries fail the run stops
 * with a message rather than sitting silent.
 */
const STALLED = Symbol("stalled");
async function insist(label, make, ms, tries) {
  for (let i = 0; i < (tries || 3); i++) {
    const r = await Promise.race([
      make(),
      new Promise((res) => setTimeout(() => res(STALLED), ms)),
    ]);
    if (r !== STALLED) return r;
    console.log(`    (${label} did not answer in ${ms} ms; re-sending)`);
  }
  throw new Error(`${label} stalled`);
}

/* -------------------------------------------------------------------- clock */
function makeClock(cdp) {
  let vt = 0;
  const budget = async (ms, policy, guardMs) => {
    const done = new Promise((r) => cdp.once("Emulation.virtualTimeBudgetExpired", r));
    await insist("setVirtualTimePolicy", () => cdp.send("Emulation.setVirtualTimePolicy", {
      policy: policy || "advance", budget: ms,
    }), 12000);
    // A real-time guard, which should never fire: `advance` does not wait on
    // anything. `pauseIfNetworkFetchesPending` was tried for the between-shot
    // pauses and abandoned — the Governance workspace keeps a fetch
    // outstanding indefinitely, which holds the clock, and a 24-virtual-second
    // settle then took over an hour of wall clock. Data arrives in real time
    // instead: `settled()` yields real milliseconds between its polls.
    await Promise.race([done, new Promise((r) => setTimeout(r, guardMs || 2500))]);
    vt += ms;
  };
  return {
    /** Take the clock over and hold it still. */
    async take() { await cdp.send("Emulation.setVirtualTimePolicy", { policy: "pause" }); },
    /** Exactly one frame of the delivered film. */
    async frame() { await budget(FRAME_MS, "advance", 8000); },
    /** Let the page work — used only between shots, never while capturing. */
    async run(ms) { await budget(ms, "advance", 4000); },
    /** Hand the clock a fixed allowance across a real page load. A paused
     *  virtual clock never fires the timers a navigation needs, but an
     *  *unbounded* `advance` is worse: the page's requestAnimationFrame loops
     *  then run as fast as the CPU allows and never stop, and the renderer
     *  stops answering evaluates and screenshots — which is what wedged three
     *  earlier passes on /enterprise-admin, /data-boundary and the reload. A
     *  budget of a few virtual seconds is all a navigation needs. */
    async free(ms) {
      await cdp.send("Emulation.setVirtualTimePolicy", { policy: "advance", budget: ms || 4000 });
    },
    get elapsed() { return vt; },
  };
}

/* ------------------------------------------------------------------ capture */
/**
 * One frame, at a 2x device scale.
 *
 * `clip` is in CSS pixels **of the document, not the viewport**, so the current
 * scroll offset has to be added or a scrolled page is captured with a black
 * band where the scrolled-off rows would be. It may be fractional, which is
 * what makes the push-in possible: `zoom` > 1 crops in and `scale` compensates,
 * so Chrome re-rasterises the page at the size it will be seen at and the
 * output is always 3840x2160.
 */
async function shoot(cdp, zoom, sx, sy, dx, dy) {
  const z = zoom || 1;
  const w = W / z, h = H / z;
  const res = await insist("captureScreenshot", () => cdp.send("Page.captureScreenshot", {
    // JPEG, not PNG: encoding a 3840x2160 PNG inside Chrome costs 400 ms a
    // frame against 160 ms for quality-96 JPEG, and the difference after the
    // lanczos downscale to 1080p measures 0.6/255 mean — invisible, and a
    // quarter of the render time. Capture is still deterministic: identical
    // pixels encode to identical bytes, so a repeated frame still reads as one.
    format: "jpeg", quality: 96,
    captureBeyondViewport: false,
    clip: {
      x: (sx || 0) + (W - w) / 2 + (dx || 0),
      y: (sy || 0) + (H - h) / 2 + (dy || 0),
      width: w, height: h, scale: 2 * z,
    },
  }), 20000);
  return Buffer.from(res.data, "base64");
}

/* ------------------------------------------------------------------ encoder */
/**
 * A segment encoder that eats JPEG frames on stdin. Capture and encode overlap,
 * and no intermediate frame is ever written to disk.
 */
function encoder(out, crf) {
  const args = ["-y", "-nostdin", "-v", "error",
    "-f", "image2pipe", "-c:v", "mjpeg", "-framerate", String(FPS), "-i", "pipe:0",
    // The captured frames are JPEG, which is full range; the delivered file is
    // limited range, so the conversion happens here, once, on the master.
    "-vf", `scale=${W}:${H}:flags=lanczos:in_range=full:out_range=tv,format=yuv420p,setsar=1`,
    // Segments are intermediates that the assembler re-encodes, so they are
    // written near-losslessly but cheaply: three x264 "medium" encodes running
    // beside three Chrome instances starve the rasteriser that actually matters.
    "-threads", "2",
    "-c:v", "libx264", "-preset", "veryfast", "-crf", String(crf == null ? 12 : crf),
    "-profile:v", "high", "-level", "4.2", "-pix_fmt", "yuv420p",
    "-r", String(FPS), "-g", "120", "-x264-params", "scenecut=0",
    "-colorspace", "bt709", "-color_primaries", "bt709", "-color_trc", "bt709",
    "-color_range", "tv", "-an", out];
  const p = spawn(FFMPEG, args, { stdio: ["pipe", "inherit", "inherit"] });
  let n = 0;
  return {
    async write(buf) {
      n++;
      if (!p.stdin.write(buf)) await new Promise((r) => p.stdin.once("drain", r));
    },
    get frames() { return n; },
    close() {
      return new Promise((res, rej) => {
        p.on("close", (c) => (c === 0 ? res(n) : rej(new Error("ffmpeg exit " + c))));
        p.stdin.end();
      });
    },
  };
}

/* ------------------------------------------------------------------ helpers */
const scrollTo = (p, y) => insist("scrollTo", () => p.evaluate((t) => {
  const max = Math.max(0, document.documentElement.scrollHeight - window.innerHeight);
  window.scrollTo({ top: Math.max(0, Math.min(t, max)), left: 0, behavior: "instant" });
}, y), 12000);

const maxScroll = (p) => p.evaluate(() =>
  Math.max(0, document.documentElement.scrollHeight - window.innerHeight));

/** Wait, on the virtual clock, until the view has painted and stopped growing. */
async function settled(page, clock, capMs) {
  const cap = capMs || 24000;
  // Both clocks are bounded: virtual time so the page's own timers get their
  // chance, real time so a view that never reports itself settled — Governance
  // holds a skeleton open — cannot stall the render.
  const deadline = Date.now() + Math.min(30000, cap);
  let waited = 0, lastH = -1, stable = 0;
  while (waited < cap && Date.now() < deadline) {
    await clock.run(220);
    // Real time, not virtual: the page's data has to arrive over a real socket,
    // and a virtual clock gives it none of its own.
    await page.waitForTimeout(70);
    waited += 220;
    const s = await insist("settle poll", () => page.evaluate(() => {
      const v = document.querySelector("#view");
      return {
        kids: v ? v.children.length : 0,
        sk: document.querySelectorAll(".sk").length,
        h: document.documentElement.scrollHeight,
        imgs: [...document.images].every((i) => i.complete),
      };
    }), 10000, 2).catch(() => null);
    if (s && s.kids >= 2 && s.sk === 0 && s.imgs && s.h === lastH) {
      if (++stable >= 3) return true;
    } else stable = 0;
    if (s) lastH = s.h;
  }
  console.log("    (settle timed out)");
  return false;
}

/**
 * Replay the console's own entrance animations. The view's children carry a
 * staggered `pnViewIn` and table rows a staggered `pnRowLand`; both have long
 * finished by the time the data has settled, so they are restarted here and
 * then filmed on the virtual clock.
 */
const replayEntrance = (p) => insist("replayEntrance", () => p.evaluate(() => {
  const targets = [...document.querySelectorAll(".view > *"), ...document.querySelectorAll("tbody tr")];
  for (const e of targets) { e.style.animation = "none"; }
  void document.body.offsetWidth;
  for (const e of targets) { e.style.animation = ""; }
}), 12000).catch(() => {});

/** A progress curve whose middle advances by the same amount every frame. */
function ramp(n, easeFrames) {
  const e = Math.max(1, Math.min(easeFrames, Math.floor(n / 2.5)));
  const smooth = (t) => t * t * (3 - 2 * t);
  const v = [];
  for (let i = 0; i < n; i++) {
    if (i < e) v.push(smooth((i + 0.5) / e));
    else if (i >= n - e) v.push(smooth((n - i - 0.5) / e));
    else v.push(1);
  }
  const total = v.reduce((a, b) => a + b, 0);
  const out = [];
  let acc = 0;
  for (let i = 0; i < n; i++) { acc += v[i]; out.push(acc / total); }
  out[n - 1] = 1;
  return out;
}

const stripTags = (s) => String(s).replace(/<[^>]+>/g, "").replace(/&amp;/g, "&").replace(/\s+/g, " ").trim();

module.exports = {
  REPO, FFMPEG, BASE, FPS, W, H, FRAME_MS, insist,
  open, makeClock, shoot, encoder, scrollTo, maxScroll, settled, replayEntrance, ramp, stripTags,
};
