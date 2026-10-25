/**
 * Renders the Morrow sixty-second film.
 *
 *   set NODE_PATH=.tools\video\node_modules
 *   node demo\video\render-60s.js [--work DIR] [--only 8-11] [--setup-from 8]
 *
 * Clock, capture and overlay are the shared kit (render-kit.js,
 * tour-overlay.js): Chrome's virtual time advanced by exactly one frame between
 * screenshots, the product's own motion left switched on, and a presentation
 * layer stepped by frame index.
 *
 * Three things are specific to this cut.
 *
 * **The product's own 3D is the spine.** `charts3d.js` draws the HNDL exposure
 * timeline, the probability ribbons, the CRQC distribution, the risk map and
 * the board gauge as real projected geometry. The renderer wraps
 * `window.airlockSpace.view` and dictates the yaw — and, where it helps, the
 * tilt — so those charts can be orbited on a curve instead of dragged. Every
 * pixel is still the product's renderer reading the product's data.
 *
 * **The camera moves in depth.** A shot's `push` is a fractional clip that
 * Chrome re-rasterises at the new scale, so the frame moves *through* the
 * picture rather than across a still of it; on the hero shot that is a push
 * through the model's Q-Day wall while the chart orbits the other way.
 *
 * **Nothing holds still.** On top of whatever a shot is doing, the capture
 * rectangle floats on a 16 px circle at half a CSS pixel a frame. The product's
 * ambient field asks for twenty frames a second, so without it two frames in
 * three would be identical wherever the field is the only thing moving.
 *
 * The grid is the music's grid: `make-promo-music.py --bars 30` runs at 120 BPM,
 * so a beat is 30 frames and a bar is 120. Every shot below is a whole number of
 * beats and they sum to 120 — sixty seconds exactly.
 */
const fs = require("fs");
const { execFileSync } = require("child_process");
const path = require("path");
const os = require("os");
const K = require("./render-kit");

const FPS = K.FPS;
const BEAT = 30;
const argv = process.argv.slice(2);
const argOf = (n, d) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : d; };
const WORK = path.resolve(argOf("--work", path.join(os.tmpdir(), "airlock-60s")));
const ONLY = argOf("--only", null);
const SETUP_FROM = Number(argOf("--setup-from", 0));
const SEG = path.join(WORK, "seg");

const A = "hl", G = "hlg", I = "hli";     // amber / green / iris spans

/* ========================================================================= */
const SHOTS = [
  /* ---- cold open · bars 0-2 ------------------------------------------- */
  {
    beats: 4, pre: async (c) => { await c.nav("overview"); await c.scroll(160); },
    scrim: { level: 0.93 }, push: 0.035,
    big: { lines: ["What you encrypt", "today"], cls: ["", ""], mode: "depth", inF: 18, stagger: 6 },
  },
  {
    beats: 4, scrim: { level: 0.93 }, push: 0.035,
    big: { lines: ["is recorded", `<span class="${A}">today</span>.`], mode: "depth", inF: 16, stagger: 6 },
  },
  {
    beats: 4, scrim: { level: 0.74 }, push: 0.04,
    big: { lines: ["Read", `<span class="${I}">later</span>.`], mode: "depth", inF: 14, stagger: 5 },
    eyebrowless: true,
  },

  /* ---- the published dates · bars 3-5 --------------------------------- */
  {
    // 980 puts the whole milestone list in frame, 2024 through 2035. Do not go
    // past 1150: the feed below it names the organisations that published each
    // hardware result, and this film names no real third party.
    beats: 5, trans: "wipeup", pre: async (c) => { await c.nav("qday"); await c.scroll(980); },
    scrim: { level: 0.52 }, push: 0.03,
    big: { lines: ['<span class="plate">2030</span>', "CNSA 2.0 · published target"],
      cls: ["xl", "mono"], mode: "depth", inF: 13, stagger: 6, justify: "center" },
    calls: [{ sel: ".card.lift", text: "Migration milestones", shape: "bracket",
      label: "THE PRODUCT'S OWN MILESTONE LIST", side: "right", at: [1.1, 2.5] }],
    verify: [{ sel: ".card.lift", text: "Migration milestones", has: "2030" }],
  },
  {
    beats: 5, trans: null, scrim: { level: 0.52 }, push: 0.03,
    big: { lines: ['<span class="plate">2035</span>', "NSM-10 · published target"],
      cls: ["xl", "mono"], mode: "depth", inF: 13, stagger: 6, justify: "center" },
    verify: [{ sel: ".card.lift", text: "Migration milestones", has: "2035" }],
  },
  {
    // The CRQC distribution, orbited. The blended figure the platform models is
    // 2031, and it is labelled a model on the chart itself.
    beats: 5, trans: "iris", pre: async (c) => { await c.nav("qday"); await c.scroll(640); },
    orbit: { key: "area", yaw: [-0.34, 0.30], secs: 2.4 }, push: 0.02,
    scrim: { level: 0.30, grad: "bottom" },
    big: { lines: ["Model Q-Day", `<span class="${I}">2031</span>.`], cls: ["md", "md"], mode: "rise", inF: 12, stagger: 5 },
    pos: "low",
  },

  /* ---- discovery · bars 6-9 ------------------------------------------- */
  {
    beats: 5, trans: "push", pre: async (c) => { await c.nav("scans"); },
    scrim: { level: 0.32, grad: "bottom" }, push: 0.022,
    big: { lines: ["Scan what you", `actually <span class="${I}">run</span>.`], cls: ["md", "md"], mode: "wipe", inF: 12, stagger: 5 },
    pos: "low",
    calls: [{ sel: ".opsPanel", shape: "bracket", label: "LIVE SCAN · 38 ENDPOINTS", side: "above", at: [0.6, 2.4] }],
  },
  {
    beats: 4, trans: null, motion: { kind: "scroll", to: 907, secs: 1.6, lead: 0.15 },
    scrim: { level: 0.3, grad: "bottom" },
    big: { lines: [`<span class="${I}">8</span> scan runs. <span class="${I}">5</span> months.`], cls: ["md"], mode: "wipe", inF: 10 },
    pos: "low",
    verify: [{ sel: ".card.lift", text: "Recent scans", has: "8 most recent" }],
  },
  {
    beats: 6, trans: "wiperight", pre: async (c) => { await c.nav("assets"); },
    scrim: { level: 0.3, grad: "bottom" }, push: 0.024,
    big: { lines: ["Every key, with an", "owner beside it."], cls: ["md", "md"], mode: "rise", inF: 12, stagger: 5 },
    pos: "low",
    counts: [{ sel: ".kpi.lift", nth: 0, at: [0.2, 1.9] }],
    calls: [{ sel: ".kpi.lift", nth: 0, shape: "box", label: "38 ASSETS · 11 OWNERS", side: "below", at: [1.7, 2.9] }],
    verify: [{ sel: ".kpi.lift", nth: 0, has: "38" }],
  },

  /* ---- exposure · bars 10-15 ------------------------------------------ */
  {
    beats: 5, trans: "push", pre: async (c) => { await c.nav("hndl"); await c.scroll(470); },
    scrim: { level: 0.3, grad: "bottom" },
    big: { lines: ["Ranked by modelled", "exposure, not severity."], cls: ["md", "md"], mode: "wipe", inF: 10, stagger: 5 },
    pos: "low",
    calls: [{ sel: "#view table tbody tr", nth: 0, shape: "box", tone: "warm",
      label: "ldap.internal.example · RSA-2048 · $2.10M", side: "below", at: [0.7, 2.4] }],
    verify: [{ sel: "#view table tbody tr", nth: 0, has: "RSA-2048" }],
  },
  {
    // The hero: the exposure timeline orbited one way while the camera pushes
    // through the model's Q-Day wall the other.
    beats: 8, trans: "fade", pre: async (c) => { await c.scroll(820); },
    orbit: { key: "timeline", yaw: [-0.36, 0.44], secs: 3.6, lead: 0.2 },
    push: 0.075,
    scrim: { level: 0.26, grad: "bottom" },
    big: { lines: ["Captured today.", `<span class="${A}">Readable after Q-Day.</span>`], cls: ["md", "md"], mode: "rise", inF: 14, stagger: 6 },
    pos: "low",
  },
  {
    beats: 6, trans: "wipeleft",
    pre: async (c) => { await c.hover(".c3d[data-c3d='curves'] canvas", 0.55, 0.45); },
    orbit: { key: "curves", yaw: [0.34, -0.26], secs: 2.8, lead: 0.2 },
    scrim: { level: 0.3, grad: "bottom" },
    big: { lines: ["One curve per algorithm.", `RSA-2048: <span class="${A}">50% by 2031</span>.`], cls: ["md", "md"], mode: "rise", inF: 12, stagger: 5 },
    pos: "low",
  },

  /* ---- evidence and action · bars 16-20 -------------------------------- */
  {
    beats: 6, trans: "push", pre: async (c) => { await c.nav("cbom"); },
    scrim: { level: 0.3, grad: "bottom" }, push: 0.024,
    big: { lines: ["A bill of materials", "an auditor can read."], cls: ["md", "md"], mode: "rise", inF: 12, stagger: 5 },
    pos: "low",
    counts: [{ sel: ".vendSummary", at: [0.2, 2.0] }],
    calls: [{ sel: ".vendSummary", shape: "bracket", tone: "good",
      label: "87 COMPONENTS · 2 ALREADY post-quantum", side: "below", at: [1.8, 2.9] }],
    verify: [{ sel: ".vendSummary", has: "87 components" }],
  },
  {
    beats: 5, trans: "wipeup", pre: async (c) => { await c.nav("remediation"); },
    scrim: { level: 0.32, grad: "bottom" }, push: 0.022,
    big: { lines: ["Suggested. Approved. PR.", `<span class="${G}">Verified closed.</span>`], cls: ["md", "md"], mode: "rise", inF: 12, stagger: 5 },
    pos: "low",
    calls: [{ sel: ".card.lift", text: "Pipeline", shape: "bracket", label: "7 OPEN · 9 TRACKED", side: "right", at: [0.6, 2.4] }],
    verify: [{ sel: ".kpi.lift", nth: 0, has: "7" }],
  },
  {
    // 120 keeps the KPI row and the relationship graph in frame together, so
    // the figure the type states is also the figure on the screen behind it.
    beats: 5, trans: "push", pre: async (c) => { await c.load("/ui/#graph"); await c.scroll(120); },
    orbit: { key: "bar", yaw: [-0.30, 0.26], secs: 2.2, lead: 0.15 },
    scrim: { level: 0.32, grad: "bottom" },
    big: { lines: ["Two roots.", `<span class="${I}">38</span> leaf certificates under them.`], cls: ["md", "md"], mode: "rise", inF: 12, stagger: 5 },
    pos: "low",
    // Matched by text rather than by position: the KPI row is built from
    // whatever the view has, and an index is not a promise.
    calls: [{ sel: ".kpi.lift", text: "Leaf certificates", shape: "box", label: "LEAF CERTIFICATES", side: "below", at: [0.6, 2.4] }],
    verify: [{ sel: ".kpi.lift", text: "Leaf certificates", has: "38" },
      { sel: ".kpi.lift", text: "Root CAs", has: "2" }],
  },
  {
    beats: 4, trans: "iris", pre: async (c) => { await c.nav("canaries"); await c.scroll(250); },
    scrim: { level: 0.32, grad: "bottom" }, push: 0.022,
    big: { lines: ["Five canaries armed.", "None tripped."], cls: ["md", "md"], mode: "rise", inF: 11, stagger: 5 },
    pos: "low",
    calls: [{ sel: ".sec", text: "Tripwire ladder", shape: "bracket", tone: "good",
      label: "ALPHA → OMEGA", side: "right", at: [0.5, 1.9] }],
    verify: [{ sel: ".sec", text: "Tripwire ladder", has: "No tier has tripped" }],
  },
  {
    beats: 6, trans: "push", pre: async (c) => { await c.nav("board"); },
    orbit: { key: "gauge", yaw: [-0.30, 0.28], secs: 2.6, lead: 0.2 },
    scrim: { level: 0.32, grad: "bottom" },
    big: { lines: ["One number for the board.", "With its working."], cls: ["md", "md"], mode: "rise", inF: 12, stagger: 5 },
    pos: "low",
    counts: [{ sel: ".kpi.lift", nth: 0, at: [0.2, 2.1] }],
    calls: [{ sel: ".kpi.lift", nth: 0, shape: "box", label: "BOARD RISK SCORE", side: "below", at: [1.9, 2.9] }],
    verify: [{ sel: ".kpi.lift", nth: 0, has: "/100" }],
  },

  /* ---- the build · bars 21-23 ----------------------------------------- */
  {
    beats: 2, trans: "bars", pre: async (c) => { await c.nav("overview"); },
    scrim: { level: 0.72 }, push: 0.05,
    big: { lines: ["DISCOVER"], cls: ["xl"], mode: "depth", inF: 7, outF: 3, justify: "center" },
  },
  { beats: 2, trans: null, scrim: { level: 0.72 }, push: 0.05,
    big: { lines: ["PRICE"], cls: ["xl"], mode: "depth", inF: 7, outF: 3, justify: "center" } },
  { beats: 2, trans: null, scrim: { level: 0.72 }, push: 0.05,
    big: { lines: ["PROVE"], cls: ["xl"], mode: "depth", inF: 7, outF: 3, justify: "center" } },
  { beats: 2, trans: null, scrim: { level: 0.72 }, push: 0.05,
    big: { lines: ["FIX"], cls: ["xl"], mode: "depth", inF: 7, outF: 3, justify: "center" } },
  { beats: 2, trans: null, scrim: { level: 0.74 }, push: 0.05,
    big: { lines: ["WATCH"], cls: ["xl"], mode: "depth", inF: 7, outF: 3, justify: "center" } },

  /* ---- the resolve · bars 24-29 --------------------------------------- */
  {
    beats: 10, trans: "iris", pre: async (c) => { await c.nav("overview"); await c.scroll(0); },
    push: 0.028,
    // The scrim is a shot-level item so it is already up when the wipe starts;
    // the card leaves it alone (scrim: null) rather than easing it from zero,
    // which showed as a flash of bright UI in the middle of the wipe.
    scrim: { level: 0.76 },
    card: { kick: "Morrow", big: "Cryptographic\ngovernance.", ruleW: 470,
      sub: "For the post-quantum migration.", scrim: null },
  },
  {
    beats: 13, trans: "fade", scrim: { level: 0.76 }, push: 0.02,
    big: { lines: ["Controlled pilot.",
      "Six to eight weeks. One organisation.",
      "Three to five critical applications."],
      cls: ["md", "tag", "tag"], mode: "rise", inF: 16, stagger: 8, outF: 40 },
  },
];

/* ========================================================================= */
(async () => {
  fs.mkdirSync(SEG, { recursive: true });
  let lo = 0, hi = SHOTS.length - 1;
  if (ONLY) { const m = /^(\d+)(?:-(\d+))?$/.exec(ONLY); lo = Number(m[1]); hi = m[2] ? Number(m[2]) : lo; }

  const frames = SHOTS.map((s) => s.beats * BEAT);
  const total = frames.reduce((a, b) => a + b, 0);
  const beats = SHOTS.reduce((a, s) => a + s.beats, 0);
  console.log(`${SHOTS.length} shots, ${beats} beats at 120 BPM, ${(total / FPS).toFixed(2)}s (${total} frames)`);
  if (beats !== 120) console.log(`  ! ${beats} beats is not the 120 the music is cut to`);

  /* The still a transition wipes away, recovered from a segment already on disk
     when a range is re-rendered on its own. */
  function lastFrameOf(segFile) {
    if (!fs.existsSync(segFile)) return null;
    try {
      const buf = execFileSync(K.FFMPEG, ["-v", "error", "-sseof", "-0.12", "-i", segFile,
        "-frames:v", "1", "-q:v", "2", "-f", "image2pipe", "-c:v", "mjpeg", "pipe:1"],
        { maxBuffer: 64 * 1024 * 1024 });
      return buf && buf.length ? "data:image/jpeg;base64," + buf.toString("base64") : null;
    } catch (e) { return null; }
  }

  const { browser, page, cdp, external } = await K.open();
  const clock = K.makeClock(cdp);

  const c = {
    page, clock,
    scroll: (y) => K.scrollTo(page, y),
    park: async () => { await page.mouse.move(1905, 1058, { steps: 3 }); await clock.run(120); },
    async nav(route) {
      await K.insist("nav " + route, () => page.evaluate((r) => {
        const b = document.querySelector(`#nav button.nav[data-go="${r}"]`);
        if (b) b.click(); else location.hash = "#" + r;
      }, route), 12000).catch(() => {});
      await clock.run(400);
      await K.settled(page, clock);
      await K.scrollTo(page, 0);
      await clock.run(600);
    },
    /* A real page load. Some views ask for data the single-page router does not
       always re-request after an in-app hop — the blast-radius KPI row came back
       "404" that way — so this shot arrives the way a person would. The clock is
       fed in small bounded chunks while the document lands: unbounded virtual
       time lets the page's animation loops run flat out and the renderer then
       stops answering. */
    async load(url) {
      let landed = false;
      const nav = page.goto(K.BASE + url, { waitUntil: "domcontentloaded" })
        .catch((e) => console.log("  goto", e.message))
        .then(() => { landed = true; });
      for (let i = 0; i < 70 && !landed; i++) {
        await clock.free(250);
        await page.waitForTimeout(80);
      }
      await nav;
      await clock.free(400);
      await page.waitForTimeout(250);
      await clock.take();
      await page.evaluate(() => window.__ov && window.__ov.mount());
      await page.evaluate(() => window.__ov.vignette(1));
      await K.settled(page, clock, 30000);
      await K.scrollTo(page, 0);
      await clock.run(600);
    },
    async hover(sel, fx, fy) {
      const b = await page.locator(sel).first().boundingBox().catch(() => null);
      if (!b) { console.log("    (no " + sel + ")"); return; }
      await page.mouse.move(b.x + b.width * fx - 30, b.y + b.height * fy - 20, { steps: 3 });
      await page.mouse.move(b.x + b.width * fx, b.y + b.height * fy, { steps: 6 });
      await clock.run(400);
    },
  };

  /** The product's own projection, with the angle dictated. */
  const installPose = () => K.insist("installPose", () => page.evaluate(() => {
    const S = window.airlockSpace;
    if (!S || S.__demoPatched) return !!S;
    const orig = S.view;
    S.view = function (ctx, w, h, opts) {
      const pose = window.__demoPose;
      if (pose) {
        const wrap = ctx && ctx.canvas && ctx.canvas.closest && ctx.canvas.closest(".c3d");
        if (wrap && wrap.dataset.c3d === pose.key) {
          opts = Object.assign({}, opts, { yaw: pose.yaw });
          if (pose.tilt != null) opts.tilt = pose.tilt;
        }
      }
      return orig.call(this, ctx, w, h, opts);
    };
    S.__demoPatched = true;
    return true;
  }), 12000).catch(() => false);

  await page.goto(`${K.BASE}/ui/#overview`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1500);
  await clock.take();
  await K.settled(page, clock, 40000);
  await c.park();
  await page.evaluate(() => window.__ov.vignette(1));

  /* The capture rectangle floats on a circle at half a CSS pixel a frame, which
     is the same rate as the slowest scroll in the long tour — a rate that
     measurably advances on every frame. A circle, not a sine: a sine has a
     turning point, and at a turning point the camera is stationary. */
  const DRIFT_PX = 0.5, DRIFT_R = 16;
  const drift = (f) => {
    const a = (f * DRIFT_PX) / DRIFT_R;
    return [Math.cos(a) * DRIFT_R, Math.sin(a) * DRIFT_R];
  };

  const manifest = [];
  let prevShot = null, at = 0;
  for (let i = 0; i < SHOTS.length; i++) {
    const s = SHOTS[i];
    const n = frames[i];
    manifest.push({ i, frames: n, seconds: n / FPS, start: at / FPS, beats: s.beats,
      text: (s.big ? s.big.lines.map(K.stripTags) : (s.card ? [s.card.kick, s.card.big.replace(/\n/g, " ")] : [])) });
    at += n;
    if (i < lo || i > hi) {
      if (i < lo && i >= SETUP_FROM) {
        if (s.pre) await s.pre(c);
        if (s.motion && s.motion.kind === "scroll") await c.scroll(s.motion.to);
      }
      prevShot = null;
      continue;
    }

    const t0 = Date.now();
    if (s.pre) {
      try { await s.pre(c); }
      catch (e) { console.log("    (setup failed: " + String(e.message).slice(0, 70) + ")"); }
    }
    await installPose();
    if (s.pre) await K.replayEntrance(page);

    // The console tweens a KPI to its value when a view mounts, so a check run
    // the instant the view appears can read a number on its way there. Each
    // assertion therefore gets a second look after the view has had a moment.
    const readFact = (v) => K.insist("verify", () => page.evaluate((q) => {
        let e = null;
        if (q.text) { for (const x of document.querySelectorAll(q.sel)) if ((x.textContent || "").includes(q.text)) { e = x; break; } }
        else e = document.querySelectorAll(q.sel)[q.nth || 0];
        return e ? (e.textContent || "").replace(/\s+/g, " ").trim().slice(0, 6000) : null;
      }, v), 12000).catch(() => null);
    for (const v of (s.verify || [])) {
      let got = await readFact(v);
      if (!got || !got.includes(v.has)) {
        await clock.run(1600);
        got = await readFact(v);
      }
      if (!got || !got.includes(v.has)) {
        console.log(`  VERIFY FAIL shot ${i}: "${v.has}" not on screen — read ${JSON.stringify((got || "").slice(0, 90))}`);
      }
    }

    const F = (sec) => Math.round(sec * FPS);
    const items = [];
    if (!prevShot && s.trans && i > 0) prevShot = lastFrameOf(path.join(SEG, String(i - 1).padStart(3, "0") + ".mp4"));
    const transF = (s.trans && prevShot) ? 18 : 0;
    if (transF) items.push({ k: "trans", a: 0, b: transF, kind: s.trans });
    if (s.scrim) items.push({ k: "scrim", a: 0, b: n, level: s.scrim.level, grad: s.scrim.grad,
      inF: 1, outF: 1 });
    if (s.card) items.push({ k: "card", a: transF, b: n, kick: s.card.kick, big: s.card.big,
      sub: s.card.sub, ruleW: s.card.ruleW, scrim: Object.prototype.hasOwnProperty.call(s.card, "scrim") ? s.card.scrim : 0.94,
      inF: 30, outF: 2 });
    if (s.big) items.push({ k: "big", a: transF + 2, b: n + (s.big.outF || 8), lines: s.big.lines,
      cls: s.big.cls, mode: s.big.mode, inF: s.big.inF, stagger: s.big.stagger, outF: s.big.outF || 8,
      justify: s.big.justify || (s.pos === "low" ? "flex-end" : "center"), align: "left" });
    for (const call of (s.calls || [])) {
      const r = await K.insist("callout rect", () => page.evaluate(
        (q) => window.__ov.rect(q.sel, { text: q.text, nth: q.nth }), call), 12000).catch(() => null);
      if (!r) { console.log(`    (no callout target ${call.sel})`); continue; }
      items.push({ k: "call", a: F(call.at[0]), b: Math.min(n, F(call.at[1])), sel: call.sel,
        text: call.text, nth: call.nth, shape: call.shape || "box", label: call.label,
        side: call.side, tone: call.tone, rect: r, drawF: 16, chipDelay: 7 });
    }
    for (const cu of (s.counts || [])) items.push({ k: "count", a: F(cu.at[0]), b: F(cu.at[1]), sel: cu.sel, nth: cu.nth });
    await K.insist("overlay begin", () => page.evaluate(
      (p) => window.__ov.begin(p), { dur: n, parallax: 1.7, items }), 15000);

    /* ---- the camera track ---- */
    const zoomOf = [], scrollOf = [], yawOf = [];
    if (s.push) for (let f = 0; f < n; f++) zoomOf.push(1 + s.push * (f / (n - 1)));
    if (s.motion && s.motion.kind === "scroll") {
      const m = s.motion;
      const from = await K.insist("scrollY", () => page.evaluate(() => Math.round(window.scrollY * 2) / 2), 12000);
      const cap = await K.insist("maxScroll", () => K.maxScroll(page), 12000);
      const to = Math.min(m.to, cap);
      const dist = Math.abs(to - from), sign = to >= from ? 1 : -1;
      const e = Math.round(0.25 * FPS);
      const step = Math.max(0.5, Math.round((dist / Math.max(1, Math.round(m.secs * FPS) - e)) * 2) / 2);
      const nm = Math.min(n, Math.max(1, Math.round(dist / step) - e) + 2 * e);
      const r = K.ramp(nm, e);
      const lead = Math.min(Math.round((m.lead != null ? m.lead : 0.2) * FPS), Math.max(0, n - nm));
      for (let f = 0; f < n; f++) {
        const j = f - lead;
        scrollOf.push(Math.round((from + sign * dist * (j < 0 ? 0 : j >= nm ? 1 : r[j])) * 2 + 1e-6) / 2);
      }
      console.log(`    scroll ${from}->${to} over ${nm}f`);
    }
    if (s.orbit) {
      const o = s.orbit;
      const nm = Math.min(n, Math.round(o.secs * FPS));
      const lead = Math.min(Math.round((o.lead || 0.2) * FPS), Math.max(0, n - nm));
      const r = K.ramp(nm, Math.round(0.35 * FPS));
      for (let f = 0; f < n; f++) {
        const j = f - lead;
        const t = j < 0 ? 0 : j >= nm ? 1 : r[j];
        yawOf.push(o.yaw[0] + (o.yaw[1] - o.yaw[0]) * t);
      }
      const d = yawOf.slice(lead + 12, lead + nm - 12);
      const st = d.slice(1).map((v, j) => Math.abs(v - d[j]));
      console.log(`    orbit ${o.key} ${o.yaw[0]} -> ${o.yaw[1]} over ${nm}f, flat step ` +
        `${st.length ? Math.min(...st).toFixed(5) : "-"}-${st.length ? Math.max(...st).toFixed(5) : "-"} rad`);
    }

    /* ---- capture ---- */
    const out = path.join(SEG, String(i).padStart(3, "0") + ".mp4");
    const enc = K.encoder(out);
    if (prevShot && transF) await page.evaluate((u) => window.__ov.setPrev(u), prevShot);
    let last = null;
    for (let f = 0; f < n; f++) {
      if (scrollOf.length) await K.scrollTo(page, scrollOf[f]);
      if (yawOf.length) {
        await K.insist("pose", () => page.evaluate((pose) => {
          window.__demoPose = pose;
          try { document.fonts.dispatchEvent(new Event("loadingdone")); } catch (e) { /* none */ }
        }, { key: s.orbit.key, yaw: yawOf[f] }), 12000);
      }
      const [dx, dy] = drift(f);
      const sc = await K.insist("overlay step", () => page.evaluate(
        (a) => { window.__ov.step(a.f, a.dx, a.dy); return { x: window.scrollX, y: window.scrollY }; },
        { f, dx, dy }), 12000);
      await clock.frame();
      // A constant 2 % crop leaves a 19 px margin inside the viewport for the
      // drift to move within, so the clip never asks for pixels that were not
      // laid out.
      const zoom = (zoomOf.length ? zoomOf[f] : 1) * 1.02;
      try {
        last = await K.shoot(cdp, zoom, sc.x, sc.y, dx, dy);
      } catch (e) {
        console.log("    (screenshot stalled at frame " + f + "; ticking and retrying)");
        await clock.frame();
        last = await K.shoot(cdp, zoom, sc.x, sc.y, dx, dy);
      }
      await enc.write(last);
    }
    await enc.close();
    if (yawOf.length) await page.evaluate(() => { window.__demoPose = null; try { document.fonts.dispatchEvent(new Event("loadingdone")); } catch (e) {} });
    await K.insist("overlay clear", () => page.evaluate(() => window.__ov.clear()), 12000).catch(() => {});
    prevShot = "data:image/jpeg;base64," + last.toString("base64");
    console.log(`${String(i + 1).padStart(2, "0")}/${SHOTS.length}  ${s.beats}b ${(n / FPS).toFixed(2)}s  ` +
      `${((Date.now() - t0) / 1000).toFixed(0)}s  ${(s.big ? K.stripTags(s.big.lines[0]) : (s.card ? s.card.kick : "")).slice(0, 44)}`);
  }

  fs.writeFileSync(path.join(WORK, "film.json"),
    JSON.stringify({ fps: FPS, beat: BEAT, bpm: 120, width: K.W, height: K.H, shots: manifest }, null, 2));
  await page.close(); await browser.close();
  console.log(external.size ? "EXTERNAL REQUESTS:\n" + [...external].join("\n") : "no external requests");
  console.log("segments in", SEG);
})().catch((e) => { console.error("FAIL", e); process.exit(1); });
