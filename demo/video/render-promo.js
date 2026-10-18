/**
 * Renders the Morrow promo — 76 seconds, cut to its own music.
 *
 *   set NODE_PATH=.tools\video\node_modules
 *   node demo\video\render-promo.js [--work DIR] [--only 4-9]
 *
 * Same clock as the tour (render-kit.js): Chrome's virtual time, advanced by
 * exactly one frame between screenshots, with the product's own motion left
 * running. Same overlay layer (tour-overlay.js), used for kinetic type here
 * rather than narration.
 *
 * The grid is the music's grid. make-promo-music.py runs at 120 BPM, so a beat
 * is 0.5 s and a bar is 2 s; every shot below is a whole number of BEATS and
 * the sum is the length of the track. Change one and change the other.
 *
 *    bars  0-3    cold open        sub pulse on the downbeat, nothing else
 *    bars  4-7    the dates        2030 and 2035, straight off the product's
 *                                  own milestone list
 *    bars  8-27   the product      fourteen cuts of it doing real things
 *    bars 28-31   the build        five words over a push, one every 1.5 s
 *    bars 32-37   the resolve      the end card, over the last chord
 */
const fs = require("fs");
const { execFileSync } = require("child_process");
const path = require("path");
const os = require("os");
const K = require("./render-kit");

const FPS = K.FPS;
const BEAT = 30;                 // frames: 0.5 s at 120 BPM
const argv = process.argv.slice(2);
const argOf = (n, d) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : d; };
const WORK = path.resolve(argOf("--work", path.join(os.tmpdir(), "airlock-promo")));
const ONLY = argOf("--only", null);
// As in the tour: shots before the range run their setup so the range starts
// from the page state it would really have had, and `--setup-from` skips the
// ones that cannot matter.
const SETUP_FROM = Number(argOf("--setup-from", 0));
const SEG = path.join(WORK, "seg");

const G = "hlg", A = "hl", I = "hli";   // green / amber / iris spans in big type

const SHOTS = [
  /* ------------------------------------------------- cold open · bars 0-3 -- */
  {
    beats: 5, pre: async (c) => { await c.nav("overview"); await c.scroll(120); },
    scrim: { level: 0.94 },
    big: { lines: ["Everything you", `encrypt <span class="${I}">today</span>`], cls: ["", ""], mode: "rise", inF: 16, stagger: 6 },
    motion: { kind: "push", amount: 0.02 },
  },
  {
    beats: 5, scrim: { level: 0.94 },
    big: { lines: ["is being recorded", `<span class="${A}">today</span>.`], mode: "rise", inF: 14, stagger: 6 },
    motion: { kind: "push", amount: 0.02 },
  },
  {
    beats: 6, scrim: { level: 0.9 },
    big: { lines: ["It becomes readable", "later."], cls: ["", A === "hl" ? "" : ""], mode: "wipe", inF: 16, stagger: 7 },
    motion: { kind: "push", amount: 0.024 },
  },

  /* ----------------------------------------------- the dates · bars 4-7 ---- */
  {
    beats: 8, trans: "wipeup",
    // 980 puts the whole milestone list in frame, 2024 through 2035, so the
    // two dates on screen can be read off the product rather than asserted.
    // Do not go past 1150: the quantum intelligence feed below it names the
    // organisations that published each hardware result.
    pre: async (c) => { await c.nav("qday"); await c.scroll(980); },
    scrim: { level: 0.58 },
    big: { lines: ["2030", "CNSA 2.0 · published target"],
      cls: ["xl", "mono"], mode: "scale", inF: 12, stagger: 6, justify: "center", align: "left" },
    calls: [{ sel: ".card.lift", text: "Migration milestones", shape: "bracket", label: "THE PRODUCT'S OWN MILESTONE LIST", side: "left", at: [1.6, 3.9] }],
    verify: [{ sel: ".card.lift", text: "Migration milestones", has: "2030" }],
  },
  {
    beats: 8, trans: null, scrim: { level: 0.58 },
    big: { lines: ["2035", "NSM-10 · published target"],
      cls: ["xl", "mono"], mode: "scale", inF: 12, stagger: 6, justify: "center", align: "left" },
    verify: [{ sel: ".card.lift", text: "Migration milestones", has: "2035" }],
  },

  /* -------------------------------------------- the product · bars 8-27 ---- */
  {
    beats: 6, trans: "iris", pre: async (c) => { await c.nav("scans"); },
    big: { lines: ["Scan what you", `actually <span class="${I}">run</span>.`], cls: ["md", "md"], mode: "wipe", inF: 12, stagger: 5 },
    pos: "low", scrim: { level: 0.34 },
    calls: [{ sel: ".opsPanel", shape: "bracket", label: "LIVE SCAN", side: "above", at: [0.5, 2.9] }],
  },
  {
    beats: 5, trans: null, motion: { kind: "scroll", to: 907, secs: 1.9, lead: 0.2 },
    big: { lines: [`<span class="${I}">8</span> runs. 5 months.`], cls: ["md"], mode: "wipe", inF: 10 },
    pos: "low", scrim: { level: 0.3 },
  },
  {
    beats: 6, trans: "push", pre: async (c) => { await c.nav("assets"); },
    big: { lines: ["Every key, with an", "owner beside it."], cls: ["md", "md"], mode: "rise", inF: 12, stagger: 5 },
    pos: "low", scrim: { level: 0.3 },
    counts: [{ sel: ".kpi.lift", nth: 0, at: [0.15, 1.7] }],
    calls: [{ sel: ".kpi.lift", nth: 0, shape: "box", label: "38 ASSETS", side: "below", at: [1.5, 2.9] }],
  },
  {
    beats: 5, trans: null, motion: { kind: "scroll", to: 620, secs: 1.9, lead: 0.2 },
    big: { lines: ["RSA-2048. P-256.", `One <span class="${G}">hybrid</span> gateway.`], cls: ["md", "md"], mode: "wipe", inF: 10, stagger: 5 },
    pos: "low", scrim: { level: 0.3 },
  },
  {
    beats: 5, trans: "wiperight", pre: async (c) => { await c.nav("hndl"); },
    big: { lines: ["Then price it."], cls: ["md"], mode: "rise", inF: 12 },
    pos: "low", scrim: { level: 0.3 },
    calls: [{ sel: ".vendSummary", shape: "bracket", label: "RISK TIERS · 38 ASSETS", side: "below", at: [0.5, 2.4] }],
  },
  {
    beats: 6, trans: null, motion: { kind: "scroll", to: 470, secs: 2.2, lead: 0.3 },
    big: { lines: ["Ranked by modelled", "exposure, not severity."], cls: ["md", "md"], mode: "wipe", inF: 10, stagger: 5 },
    pos: "low", scrim: { level: 0.32 },
  },
  {
    // The hero shot: the exposure timeline turning through the model's Q-Day
    // wall, drawn by the product's own renderer.
    beats: 8, trans: "fade", pre: async (c) => { await c.scroll(820); },
    motion: { kind: "rotate", key: "timeline", from: -0.20, to: 0.48, secs: 3.2, hold: 0.2, back: false, lead: 0.3 },
    big: { lines: ["Captured today.", `<span class="${A}">Readable after Q-Day.</span>`], cls: ["md", "md"], mode: "rise", inF: 14, stagger: 6 },
    pos: "low", scrim: { level: 0.28 },
  },
  {
    beats: 5, trans: "wipeleft", pre: async (c) => { await c.hover(".c3d[data-c3d='curves'] canvas", 0.55, 0.45); },
    big: { lines: ["One curve per algorithm."], cls: ["md"], mode: "wipe", inF: 10 },
    pos: "low", scrim: { level: 0.3 },
  },
  {
    beats: 6, trans: "push", pre: async (c) => { await c.nav("cbom"); },
    big: { lines: ["A bill of materials", "an auditor can read."], cls: ["md", "md"], mode: "rise", inF: 12, stagger: 5 },
    pos: "low", scrim: { level: 0.3 },
    counts: [{ sel: ".vendSummary", at: [0.15, 1.8] }],
    calls: [{ sel: ".vendSummary", shape: "bracket", label: "87 COMPONENTS · CYCLONEDX 1.6", side: "below", at: [1.6, 2.9] }],
    verify: [{ sel: ".vendSummary", has: "87 components" }],
  },
  {
    beats: 5, trans: "wipeup", pre: async (c) => { await c.nav("governance"); await c.tab("Compliance"); },
    big: { lines: ["Mapped to the frameworks", "you are judged on."], cls: ["md", "md"], mode: "wipe", inF: 10, stagger: 5 },
    pos: "low", scrim: { level: 0.34 },
  },
  {
    beats: 6, trans: "push", pre: async (c) => { await c.nav("remediation"); },
    big: { lines: ["Suggested. Approved.", `PR. <span class="${G}">Verified closed.</span>`], cls: ["md", "md"], mode: "rise", inF: 12, stagger: 5 },
    pos: "low", scrim: { level: 0.32 },
    calls: [{ sel: ".card.lift", text: "Pipeline", shape: "bracket", label: "PIPELINE", side: "right", at: [0.6, 2.9] }],
  },
  {
    beats: 5, trans: "wiperight", pre: async (c) => { await c.nav("graph"); await c.scroll(330); },
    big: { lines: ["Know what depends", "on the authority."], cls: ["md", "md"], mode: "wipe", inF: 10, stagger: 5 },
    pos: "low", scrim: { level: 0.32 },
  },
  {
    beats: 6, trans: "iris", pre: async (c) => { await c.nav("canaries"); await c.scroll(260); },
    big: { lines: ["Five canaries.", "Five strengths. Armed."], cls: ["md", "md"], mode: "rise", inF: 12, stagger: 5 },
    pos: "low", scrim: { level: 0.32 },
    calls: [{ sel: ".sec", text: "Tripwire ladder", shape: "bracket", label: "NO TIER HAS TRIPPED", side: "right", at: [0.8, 2.9] }],
  },
  {
    beats: 6, trans: "push", pre: async (c) => { await c.nav("board"); },
    big: { lines: ["And one number", "for the board."], cls: ["md", "md"], mode: "rise", inF: 12, stagger: 5 },
    pos: "low", scrim: { level: 0.32 },
    counts: [{ sel: ".kpi.lift", nth: 0, at: [0.15, 1.9] }],
    calls: [{ sel: ".kpi.lift", nth: 0, shape: "box", label: "BOARD RISK SCORE", side: "below", at: [1.7, 2.9] }],
  },

  /* ------------------------------------------------ the build · bars 28-31 - */
  {
    beats: 3, trans: "bars", pre: async (c) => { await c.nav("overview"); },
    scrim: { level: 0.82 }, motion: { kind: "push", amount: 0.03 },
    big: { lines: ["DISCOVER"], cls: ["xl"], mode: "scale", inF: 8, outF: 4, justify: "center" },
  },
  { beats: 3, trans: null, scrim: { level: 0.82 }, motion: { kind: "push", amount: 0.03 },
    big: { lines: ["PRICE"], cls: ["xl"], mode: "scale", inF: 8, outF: 4, justify: "center" } },
  { beats: 3, trans: null, scrim: { level: 0.82 }, motion: { kind: "push", amount: 0.03 },
    big: { lines: ["PROVE"], cls: ["xl"], mode: "scale", inF: 8, outF: 4, justify: "center" } },
  { beats: 3, trans: null, scrim: { level: 0.82 }, motion: { kind: "push", amount: 0.03 },
    big: { lines: ["FIX"], cls: ["xl"], mode: "scale", inF: 8, outF: 4, justify: "center" } },
  { beats: 4, trans: null, scrim: { level: 0.86 }, motion: { kind: "push", amount: 0.03 },
    big: { lines: ["WATCH"], cls: ["xl"], mode: "scale", inF: 8, outF: 6, justify: "center" } },

  /* ---------------------------------------------- the resolve · bars 32-37 - */
  {
    beats: 14, trans: "iris", pre: async (c) => { await c.nav("overview"); await c.scroll(0); },
    motion: { kind: "push", amount: 0.022 },
    card: { kick: "Morrow", big: "Cryptographic\ngovernance.", ruleW: 460,
      sub: "For the post-quantum migration." },
  },
  {
    beats: 10, trans: "fade", scrim: { level: 0.95 },
    big: { lines: ["Controlled pilot.",
      "Six to eight weeks. One organisation.",
      "Three to five critical applications."],
      cls: ["md", "tag", "tag"], mode: "rise", inF: 16, stagger: 8, outF: 30 },
    motion: { kind: "push", amount: 0.018 },
  },
];


/**
 * The still a transition wipes away is normally the last frame of the shot
 * just captured. When a range is re-rendered on its own, that shot was not
 * captured in this run — so the frame is pulled out of the segment already on
 * disk instead, and the join survives. It comes back at 1920x1080 rather than
 * at the 2x capture scale, which costs nothing visible: it is on screen for
 * 0.43 s, moving, and under the incoming picture.
 */
function lastFrameOf(segFile) {
  if (!fs.existsSync(segFile)) return null;
  try {
    const buf = execFileSync(K.FFMPEG, ["-v", "error", "-sseof", "-0.12", "-i", segFile,
      "-frames:v", "1", "-q:v", "2", "-f", "image2pipe", "-c:v", "mjpeg", "pipe:1"],
      { maxBuffer: 64 * 1024 * 1024 });
    return buf && buf.length ? "data:image/jpeg;base64," + buf.toString("base64") : null;
  } catch (e) {
    console.log("    (no previous frame for the transition: " + String(e.message).slice(0, 60) + ")");
    return null;
  }
}

/* ================================================================== renderer */
(async () => {
  fs.mkdirSync(SEG, { recursive: true });
  let lo = 0, hi = SHOTS.length - 1;
  if (ONLY) { const m = /^(\d+)(?:-(\d+))?$/.exec(ONLY); lo = Number(m[1]); hi = m[2] ? Number(m[2]) : lo; }

  const frames = SHOTS.map((s) => s.beats * BEAT);
  const total = frames.reduce((a, b) => a + b, 0);
  console.log(`${SHOTS.length} shots, ${SHOTS.reduce((a, s) => a + s.beats, 0)} beats, ` +
    `${(total / FPS).toFixed(2)}s (${total} frames)`);

  const { browser, page, cdp, external } = await K.open();
  const clock = K.makeClock(cdp);
  const c = {
    page, clock,
    scroll: (y) => K.scrollTo(page, y),
    park: async () => { await page.mouse.move(1905, 1058, { steps: 3 }); await clock.run(120); },
    async nav(route) {
      await page.evaluate((r) => {
        const b = document.querySelector(`#nav button.nav[data-go="${r}"]`);
        if (b) b.click(); else location.hash = "#" + r;
      }, route);
      await clock.run(400);
      await K.settled(page, clock);
      await K.scrollTo(page, 0);
      await clock.run(600);
    },
    async tab(label) {
      const ok = await page.evaluate((t) => {
        for (const b of document.querySelectorAll(".tabs button")) {
          if ((b.textContent || "").trim() === t) { b.click(); return true; }
        }
        return false;
      }, label);
      if (!ok) console.log(`    (no tab "${label}")`);
      await clock.run(500);
      await K.settled(page, clock);
      await clock.run(400);
    },
    async hover(sel, fx, fy) {
      const b = await page.locator(sel).first().boundingBox().catch(() => null);
      if (!b) { console.log("    (no " + sel + ")"); return null; }
      await page.mouse.move(b.x + b.width * fx - 30, b.y + b.height * fy - 20, { steps: 3 });
      await page.mouse.move(b.x + b.width * fx, b.y + b.height * fy, { steps: 6 });
      await clock.run(400);
      return null;
    },
  };

  const installPose = () => page.evaluate(() => {
    const S = window.airlockSpace;
    if (!S || S.__demoPatched) return !!S;
    const orig = S.view;
    S.view = function (ctx, w, h, opts) {
      const pose = window.__demoPose;
      if (pose) {
        const wrap = ctx && ctx.canvas && ctx.canvas.closest && ctx.canvas.closest(".c3d");
        if (wrap && wrap.dataset.c3d === pose.key) opts = Object.assign({}, opts, { yaw: pose.yaw });
      }
      return orig.call(this, ctx, w, h, opts);
    };
    S.__demoPatched = true;
    return true;
  }).catch(() => false);

  await page.goto(`${K.BASE}/ui/#overview`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1500);
  await clock.take();
  await K.settled(page, clock, 40000);
  await c.park();

  const manifest = [];
  let prevShot = null;
  let at = 0;
  for (let i = 0; i < SHOTS.length; i++) {
    const s = SHOTS[i];
    const n = frames[i];
    manifest.push({ i, frames: n, seconds: n / FPS, start: at / FPS, beats: s.beats });
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
    if (s.pre) { await s.pre(c); await installPose(); await K.replayEntrance(page); }
    else await installPose();

    for (const v of (s.verify || [])) {
      const got = await page.evaluate((q) => {
        let e = null;
        if (q.text) { for (const x of document.querySelectorAll(q.sel)) if ((x.textContent || "").includes(q.text)) { e = x; break; } }
        else e = document.querySelectorAll(q.sel)[q.nth || 0];
        return e ? (e.textContent || "").replace(/\s+/g, " ").trim().slice(0, 6000) : null;
      }, v);
      if (!got || !got.includes(v.has)) console.log(`  VERIFY FAIL shot ${i}: "${v.has}" missing`);
    }

    const F = (sec) => Math.round(sec * FPS);
    const items = [];
    if (!prevShot && s.trans && i > 0) {
      prevShot = lastFrameOf(path.join(SEG, String(i - 1).padStart(3, "0") + ".mp4"));
    }
    const transF = (s.trans && prevShot) ? 18 : 0;
    if (transF) items.push({ k: "trans", a: 0, b: transF, kind: s.trans });
    // A scrim that is already up when the shot before it carried one must not
    // pump at the cut, so it only fades in where there is a transition.
    if (s.scrim) items.push({ k: "scrim", a: 0, b: n, level: s.scrim.level, flat: s.scrim.flat,
      grad: s.scrim.grad || (s.pos === "low" ? "bottom" : null), inF: s.trans ? 10 : 1, outF: 1 });
    if (s.card) {
      items.push({ k: "card", a: transF, b: n, kick: s.card.kick, big: s.card.big, sub: s.card.sub,
        ruleW: s.card.ruleW, scrim: s.card.scrim == null ? 0.95 : s.card.scrim, inF: 30, outF: 2 });
    }
    if (s.big) {
      // The type holds to the cut: a hard cut on the beat is the edit, not a fade.
      items.push({ k: "big", a: transF + 2, b: n + (s.big.outF || 8), lines: s.big.lines, cls: s.big.cls,
        mode: s.big.mode, inF: s.big.inF, stagger: s.big.stagger, outF: s.big.outF || 8,
        justify: s.big.justify || (s.pos === "low" ? "flex-end" : "center"),
        align: s.big.align || "left" });
    }
    for (const call of (s.calls || [])) {
      const r = await page.evaluate((q) => window.__ov.rect(q.sel, { text: q.text, nth: q.nth }), call);
      if (!r) { console.log(`    (no callout target ${call.sel})`); continue; }
      items.push({ k: "call", a: F(call.at[0]), b: Math.min(n, F(call.at[1])), sel: call.sel, text: call.text,
        nth: call.nth, shape: call.shape || "box", label: call.label, side: call.side, rect: r, drawF: 16, chipDelay: 8 });
    }
    for (const cu of (s.counts || [])) items.push({ k: "count", a: F(cu.at[0]), b: F(cu.at[1]), sel: cu.sel, nth: cu.nth });
    await K.insist("overlay begin", () => page.evaluate((p) => window.__ov.begin(p), { dur: n, items }), 15000);

    const zoomOf = [], scrollOf = [], yawOf = [];
    // Every shot moves: see the note in render-tour.js. A held frame over the
    // product's 20 fps ambient field repeats, and a promo cannot repeat frames.
    const m = s.motion || { kind: "push", amount: 0.022 };
    if (m && m.kind === "push") for (let f = 0; f < n; f++) zoomOf.push(1 + m.amount * (f / (n - 1)));
    if (m && m.kind === "scroll") {
      const from = await page.evaluate(() => Math.round(window.scrollY * 2) / 2);
      const cap = await K.maxScroll(page);
      const to = Math.min(m.to, cap);
      const dist = Math.abs(to - from), sign = to >= from ? 1 : -1;
      const e = Math.round(0.28 * FPS);
      const want = Math.max(1, Math.round(m.secs * FPS));
      const step = Math.max(0.5, Math.round((dist / Math.max(1, want - e)) * 2) / 2);
      const nm = Math.min(n, Math.max(1, Math.round(dist / step) - e) + 2 * e);
      const r = K.ramp(nm, e);
      const lead = Math.min(Math.round((m.lead != null ? m.lead : 0.3) * FPS), Math.max(0, n - nm));
      for (let f = 0; f < n; f++) {
        const j = f - lead;
        const t = j < 0 ? 0 : j >= nm ? 1 : r[j];
        scrollOf.push(Math.round((from + sign * dist * t) * 2 + 1e-6) / 2);
      }
      console.log(`    scroll ${from}->${to} over ${nm}f`);
    }
    if (m && m.kind === "rotate") {
      const nm = Math.min(n, Math.round(m.secs * FPS));
      const lead = Math.min(Math.round((m.lead || 0.3) * FPS), Math.max(0, n - nm));
      const r = K.ramp(nm, Math.round(0.3 * FPS));
      for (let f = 0; f < n; f++) {
        const j = f - lead;
        const t = j < 0 ? 0 : j >= nm ? 1 : r[j];
        yawOf.push(m.from + (m.to - m.from) * t);
      }
      console.log(`    rotate ${m.key} ${m.from}->${m.to} over ${nm}f`);
    }

    const out = path.join(SEG, String(i).padStart(3, "0") + ".mp4");
    const enc = K.encoder(out);
    if (prevShot && transF) await page.evaluate((u) => window.__ov.setPrev(u), prevShot);
    let last = null;
    for (let f = 0; f < n; f++) {
      if (scrollOf.length) await K.scrollTo(page, scrollOf[f]);
      if (yawOf.length) {
        await page.evaluate((pose) => {
          window.__demoPose = pose;
          try { document.fonts.dispatchEvent(new Event("loadingdone")); } catch (e) { /* none */ }
        }, { key: m.key, yaw: yawOf[f] });
      }
      // The overlay step and the scroll read share one round trip; the clip
      // rectangle is in document coordinates, so it needs the scroll offset.
      const sc = await K.insist("overlay step", () => page.evaluate((k) => {
        window.__ov.step(k);
        return { x: window.scrollX, y: window.scrollY };
      }, f), 12000);
      await clock.frame();
      try {
        last = await K.shoot(cdp, zoomOf.length ? zoomOf[f] : 1, sc.x, sc.y);
      } catch (e) {
        console.log("    (screenshot stalled at frame " + f + "; ticking and retrying)");
        await clock.frame();
        last = await K.shoot(cdp, zoomOf.length ? zoomOf[f] : 1, sc.x, sc.y);
      }
      await enc.write(last);
    }
    await enc.close();
    if (yawOf.length) await page.evaluate(() => { window.__demoPose = null; try { document.fonts.dispatchEvent(new Event("loadingdone")); } catch (e) {} });
    await page.evaluate(() => window.__ov.clear());
    // `Memory.forciblyPurgeJavaScriptMemory` was tried here and removed: on the
    // pages that carry a WebGL scene it leaves the renderer unable to answer an
    // evaluate for minutes afterwards. Dropping the outgoing-frame bitmap in
    // `__ov.clear()` is what actually mattered.
    prevShot = "data:image/jpeg;base64," + last.toString("base64");
    console.log(`${String(i + 1).padStart(2, "0")}/${SHOTS.length}  ${s.beats}b ${(n / FPS).toFixed(2)}s  ` +
      `${((Date.now() - t0) / 1000).toFixed(0)}s  ${(s.big ? K.stripTags(s.big.lines[0]) : (s.card ? s.card.kick : "")).slice(0, 42)}`);
  }

  fs.writeFileSync(path.join(WORK, "promo.json"),
    JSON.stringify({ fps: FPS, beat: BEAT, bpm: 120, width: K.W, height: K.H, shots: manifest }, null, 2));
  await page.close(); await browser.close();
  console.log(external.size ? "EXTERNAL REQUESTS:\n" + [...external].join("\n") : "no external requests");
  console.log("segments in", SEG);
})().catch((e) => { console.error("FAIL", e); process.exit(1); });
