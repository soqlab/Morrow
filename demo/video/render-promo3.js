/**
 * Renders the Morrow three-minute film.
 *
 *   set NODE_PATH=.tools\video\node_modules
 *   node demo\video\render-3min.js [--work DIR] [--only 8-11] [--setup-from 8]
 *
 * Clock and capture are the shared kit (render-kit.js): Chrome's virtual time
 * advanced by exactly one frame between screenshots, with the product's own
 * motion left running, and a presentation layer (tour-overlay.js) stepped by
 * frame index.
 *
 * ## No circular motion, anywhere
 *
 * The sixty-second cut floated the capture rectangle on a 16 px circle so that
 * no frame could repeat. It read as the whole picture swimming, and it is gone.
 * Everything that moves here moves in a straight line or not at all:
 *
 *   * **truck** — the capture rectangle travels a straight diagonal across the
 *     margin reserved by the base crop, at half a CSS pixel a frame or more, so
 *     every frame still differs from the one before it. Its direction alternates
 *     from shot to shot instead of looping.
 *   * **dolly** — a linear change of the clip scale: in on some shots, out on
 *     others. Chrome re-rasterises at each scale, so this is a move through the
 *     picture, not a crop of a still.
 *   * **reveal** — a 3D chart turns once, from a stated angle to a stated angle,
 *     and stops. Never a continuous spin, and never on a shot that is also
 *     dollying; the renderer refuses to do both and says so.
 *   * **rack focus** — the plane behind the words goes from soft to sharp, which
 *     is a change in depth rather than in position.
 *
 * The console's own constellation field — a drifting, pulsing point cloud — is
 * switched off through the product's own control, `airlockFabric.setRunning`,
 * the same one the pause button in the console uses. The ops panels, the chart
 * grow-ins, the row entrances and the CSS sweeps all keep running.
 *
 * ## Depth
 *
 * `focus` puts a real backdrop blur on the plane behind the type (an element
 * outside the overlay's containment, since `contain: strict` would otherwise
 * give the filter nothing to sample). Narrative beats sit the product behind
 * the words, soft and dim; the beat that is about what the product *does* racks
 * it sharp and fills the frame with it.
 *
 * The grid is the music's: make-film-music.py runs at 120 BPM over 90 bars, so
 * a beat is 30 frames and the shots below sum to 360 beats — three minutes.
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
const WORK = path.resolve(argOf("--work", path.join(os.tmpdir(), "morrow-promo3")));
const ONLY = argOf("--only", null);
const SETUP_FROM = Number(argOf("--setup-from", 0));
const SEG = path.join(WORK, "seg");

/* The base crop. It reserves the margin the truck travels across: 87 px to
   either side and 49 px above and below, in CSS pixels. */
const BASE_Z = 1.10;
const MX = (K.W - K.W / BASE_Z) / 2 - 7;      // 80
const MY = (K.H - K.H / BASE_Z) / 2 - 5;      // 44

const A = "hl", G = "hlg", I = "hli";

/* Narrative look: the product behind the words, dim and soft.
   Product look: the product sharp, with only enough scrim to hold type. */
const STORY = (blur) => ({ level: 0.74, blur: blur || [13, 8] });
const SHOW = { level: 0.28, grad: "bottom" };
const SHOW_SOFT = { level: 0.34, grad: "bottom", blur: [3.5, 0] };

/* ===========================================================================
   Morrow — three-minute commercial.

   360 beats at 120 BPM = 180.00 s exactly, which is what make-film-music.py
   scores to. Change a beat count and the music stops landing on the cuts.

   Four acts:
     one    the problem, the product dim behind the words            56 beats
     two    one domain, free, and the record it leaves               78 beats
     three  the whole estate                                        131 beats
     four   free and open, and the honest half of that               96 beats

   The record at /r/example.com is seeded by seed-promo-record.py and renders
   from stored data, so nothing in this film opens a connection to anybody.
   example.com is IANA-reserved (RFC 2606), like every hostname in the demo
   estate. No real third party is named anywhere.

   Two rules the earlier cuts established and this one keeps: a shot either
   dollies or turns a chart, never both (that reads as an orbit), and the
   constellation field is stopped, because the user asked for the thing that
   loops in the background to go.
   ========================================================================= */
const SHOTS = [
  /* ============== ACT ONE · the problem ================== 56 beats ====== */
  {
    beats: 6, pre: async (c) => { await c.nav("overview"); await c.scroll(180); },
    scrim: STORY([17, 13]), dolly: [1.0, 1.035],
    big: { lines: ["Everything you send", "is encrypted."], cls: ["", ""], mode: "depth", inF: 20, stagger: 7 },
  },
  {
    beats: 6, scrim: STORY([13, 10]), dolly: [1.035, 1.0],
    big: { lines: ["The encryption you", "trust today"], mode: "depth", inF: 18, stagger: 7 },
  },
  {
    beats: 7, scrim: STORY([10, 8]), dolly: [1.0, 1.04],
    big: { lines: ["can be copied today,", `and <span class="${A}">kept</span>.`], mode: "depth", inF: 18, stagger: 7 },
  },
  {
    beats: 8, trans: "wipeleft", scrim: STORY([8, 5]), dolly: [1.04, 1.0],
    big: { lines: ["Harvest now, decrypt later.",
      "The key is broken years after the traffic was taken."],
      cls: ["md", "tag"], mode: "rise", inF: 16, stagger: 9 },
  },
  {
    /* The product takes the frame for the first time. */
    beats: 8, trans: "push", pre: async (c) => { await c.nav("overview"); await c.scroll(0); },
    scrim: SHOW_SOFT, dolly: [1.0, 1.03],
    calls: [{ sel: ".metricRow", shape: "bracket", label: "ONE ESTATE · 38 ASSETS", side: "below", at: [2.2, 3.8] }],
  },
  {
    beats: 7, trans: "wiperight", pre: async (c) => { await c.nav("qday"); await c.scroll(980); },
    scrim: SHOW, motion: { kind: "scroll", to: 1180, secs: 2.4, lead: 0.3 },
    calls: [{ sel: ".card.lift", shape: "bracket",
      label: "THE PUBLISHED DEADLINES, QUOTED", side: "right", at: [1.4, 3.4] }],
  },
  {
    beats: 8, trans: null, scrim: STORY([8, 6]), dolly: [1.0, 1.03],
    big: { lines: ["The deadlines are published.",
      "What nobody can tell you is what you are actually running."],
      cls: ["md", "tag"], mode: "rise", inF: 16, stagger: 9 },
  },
  {
    beats: 6, trans: "wipeup", scrim: STORY([7, 5]), dolly: [1.03, 1.0],
    big: { lines: ["So start smaller than that."], cls: ["md"], mode: "rise", inF: 14, stagger: 0 },
  },

  /* ============== ACT TWO · one domain ==================== 78 beats ===== */
  {
    beats: 8, still: true, trans: "push", pre: async (c) => { await c.load("/check"); },
    scrim: SHOW_SOFT, dolly: [1.0, 1.025],
    calls: [{ sel: ".check-form", shape: "bracket", label: "ONE DOMAIN. NO ACCOUNT.", side: "below", at: [1.6, 3.8] }],
  },
  {
    beats: 7, still: true, trans: null, scrim: SHOW, motion: { kind: "scroll", to: 520, secs: 2.4, lead: 0.3 },
    calls: [{ sel: ".check-row", shape: "box", label: "WHAT IT WILL AND WILL NOT TOUCH", side: "below", at: [1.4, 3.6] }],
  },
  {
    beats: 8, still: true, trans: null, scrim: STORY([8, 6]), dolly: [1.0, 1.03],
    big: { lines: ["No account. No card.", "Nothing to install."], cls: ["md", "md"], mode: "rise", inF: 15, stagger: 8 },
  },
  {
    /* The record. Rendered from the register, which is why a link to it keeps
       working — the point the next three shots make. */
    beats: 8, still: true, trans: "push", pre: async (c) => { await c.load("/r/example.com"); },
    scrim: SHOW_SOFT, dolly: [1.0, 1.025],
    calls: [{ sel: ".posture-line", shape: "bracket", label: "HYBRID · X25519MLKEM768", side: "right", at: [1.4, 3.6] }],
  },
  {
    beats: 8, still: true, trans: null, scrim: SHOW, motion: { kind: "scroll", to: 980, secs: 2.8, lead: 0.3 },
    calls: [{ sel: ".algo-grid", shape: "bracket", label: "ML-KEM-768 · FIPS 203", side: "below", at: [1.4, 3.8] }],
  },
  {
    beats: 8, still: true, trans: null, pre: async (c) => { await c.load("/r/example.com"); await c.scroll(2230); },
    scrim: SHOW,
    calls: [{ sel: ".history", shape: "bracket", label: "JULY: RSA-2048 · OCTOBER: HYBRID", side: "above", at: [1.2, 3.8] }],
  },
  {
    beats: 8, still: true, trans: null, scrim: STORY([8, 6]), dolly: [1.0, 1.03],
    big: { lines: ["In July it was classical.",
      "The record says so, and it still will in five years."],
      cls: ["md", "tag"], mode: "rise", inF: 16, stagger: 9 },
  },
  {
    beats: 7, still: true, trans: "wipeup", pre: async (c) => { await c.load("/r/example.com"); await c.scroll(2650); },
    scrim: SHOW,
    calls: [{ sel: "pre", shape: "box", label: "A BADGE FOR YOUR README", side: "above", at: [1.2, 3.6] }],
  },
  {
    beats: 7, still: true, trans: null, scrim: STORY([7, 5]), dolly: [1.03, 1.0],
    big: { lines: ["Link it. Cite it.", "Put it in your README."], cls: ["md", "md"], mode: "rise", inF: 14, stagger: 8 },
  },
  {
    beats: 9, still: true, trans: "wipeleft", scrim: STORY([8, 6]), dolly: [1.03, 1.0],
    big: { lines: ["Then the whole estate."], cls: ["md"], mode: "rise", inF: 14, stagger: 0 },
  },

  /* ============== ACT THREE · the estate ================== 131 beats ==== */
  {
    beats: 8, trans: "push", pre: async (c) => { await c.nav("assets"); },
    scrim: SHOW, motion: { kind: "scroll", to: 600, secs: 2.8, lead: 0.3 },
    calls: [{ sel: ".kpi.lift", nth: 0, shape: "box", label: "38 ASSETS · 11 OWNERS", side: "below", at: [2.0, 3.8] }],
  },
  {
    beats: 8, trans: "push", pre: async (c) => { await c.nav("scans"); },
    scrim: SHOW, motion: { kind: "scroll", to: 907, secs: 2.6, lead: 0.3 },
    calls: [{ sel: ".opsPanel", shape: "bracket", label: "EVERY ENDPOINT, AS MEASURED", side: "above", at: [1.0, 3.6] }],
  },
  {
    beats: 9, trans: "wipeup", pre: async (c) => { await c.nav("hndl"); },
    scrim: SHOW_SOFT, reveal: { key: "timeline", yaw: [-0.34, 0.30], secs: 4.6, lead: 0.7 },
  },
  {
    beats: 8, trans: null, scrim: SHOW_SOFT, reveal: { key: "curves", yaw: [0.30, -0.18], secs: 3.4, lead: 0.5 },
  },
  {
    beats: 8, trans: null, pre: async (c) => { await c.nav("hndl"); await c.scroll(820); },
    scrim: SHOW,
    calls: [{ sel: ".vendSummary", shape: "bracket",
      label: "RSA-2048 · 15-YEAR SECRECY · HARVESTABLE TODAY", side: "below", at: [1.4, 3.8] }],
  },
  {
    beats: 8, trans: null, scrim: STORY([8, 6]), dolly: [1.0, 1.03],
    big: { lines: ["Harvest-now exposure, per endpoint,",
      "with the model's assumptions printed beside it."],
      cls: ["md", "tag"], mode: "rise", inF: 16, stagger: 9 },
  },
  {
    beats: 8, trans: "push", pre: async (c) => { await c.nav("cbom"); },
    scrim: SHOW, motion: { kind: "scroll", to: 540, secs: 2.6, lead: 0.3 },
    calls: [{ sel: ".card.lift", shape: "bracket",
      label: "CYCLONEDX 1.6 · GENERATED FROM THE SCANS", side: "below", at: [1.4, 3.8] }],
  },
  {
    beats: 8, trans: null, pre: async (c) => { await c.nav("cbom"); await c.tab("Compliance"); },
    scrim: SHOW,
    calls: [{ sel: ".card.lift", shape: "bracket",
      label: "MAPPED TO THE FRAMEWORKS YOU ARE JUDGED ON", side: "below", at: [1.4, 3.8] }],
  },
  {
    beats: 8, trans: "push", pre: async (c) => { await c.nav("remediation"); },
    scrim: SHOW,
    calls: [{ sel: ".card.lift", text: "Pipeline", shape: "bracket",
      label: "7 OPEN · 9 CARRIED TO CLOSURE", side: "right", at: [1.2, 3.8] }],
  },
  {
    /* Canaries, framed the way the proven film frames them: the tripwire ladder. */
    beats: 8, trans: "wipeup", pre: async (c) => { await c.nav("canaries"); await c.scroll(250); },
    scrim: SHOW, dolly: [1.0, 1.035],
    calls: [{ sel: ".sec", text: "Tripwire ladder", shape: "bracket", tone: "good",
      label: "ALPHA → OMEGA · NO TIER HAS TRIPPED", side: "right", at: [1.2, 3.8] }],
  },
  {
    /* The gauge chart lives on the board, not on canaries. Turning a chart that is
       not on the page waits forever for it, which is what stalled the first pass. */
    beats: 8, trans: "push", pre: async (c) => { await c.nav("board"); },
    scrim: SHOW_SOFT, reveal: { key: "gauge", yaw: [-0.26, 0.18], secs: 2.2, lead: 0.3 },
  },
  {
    beats: 8, trans: null, scrim: SHOW, dolly: [1.0, 1.035],
    calls: [{ sel: ".card.lift", text: "Score composition", shape: "bracket",
      label: "EVERY WEIGHT, SHOWN", side: "right", at: [0.8, 2.9] }],
  },
  {
    beats: 9, trans: null, scrim: STORY([8, 6]), dolly: [1.0, 1.03],
    big: { lines: ["Evidence an auditor can read.",
      "Not a score you have to take on trust."],
      cls: ["md", "tag"], mode: "rise", inF: 16, stagger: 9 },
  },
  {
    beats: 8, trans: "wiperight", pre: async (c) => { await c.nav("qday"); await c.scroll(640); },
    scrim: SHOW_SOFT, reveal: { key: "area", yaw: [-0.30, 0.16], secs: 3.0, lead: 0.5 },
  },
  {
    beats: 8, trans: null, scrim: STORY([8, 6]), dolly: [1.03, 1.0],
    big: { lines: ["And where it is a model,", "it says so."], cls: ["md", "md"], mode: "rise", inF: 15, stagger: 8 },
  },
  {
    beats: 8, trans: null, scrim: STORY([7, 5]), dolly: [1.0, 1.03],
    big: { lines: ["A failed check is never", `reported as a <span class="${A}">clean</span> one.`],
      cls: ["md", "md"], mode: "rise", inF: 15, stagger: 8 },
  },

  /* ============== ACT FOUR · free and open ================ 96 beats ===== */
  {
    beats: 8, still: true, trans: "push", pre: async (c) => { await c.load("/pricing"); },
    scrim: SHOW_SOFT, dolly: [1.0, 1.025],
    calls: [{ sel: ".doc-hero", shape: "bracket", label: "PRICING", side: "below", at: [1.6, 3.6] }],
  },
  {
    beats: 8, still: true, trans: null, scrim: STORY([9, 7]), dolly: [1.0, 1.03],
    big: { lines: ["There isn’t any."], cls: [""], mode: "depth", inF: 18, stagger: 0 },
  },
  {
    beats: 8, still: true, trans: null, pre: async (c) => { await c.load("/pricing"); await c.scroll(300); },
    scrim: SHOW,
    calls: [{ sel: ".matrix", shape: "bracket", label: "THREE WAYS IN · NONE OF THEM PAID", side: "below", at: [1.4, 3.8] }],
  },
  {
    beats: 8, still: true, trans: null, scrim: STORY([8, 6]), dolly: [1.03, 1.0],
    big: { lines: ["The hosted service is free.", "The platform is MIT."], cls: ["md", "md"], mode: "rise", inF: 15, stagger: 8 },
  },
  {
    beats: 8, still: true, trans: null, scrim: STORY([7, 5]), dolly: [1.0, 1.03],
    big: { lines: ["Clone it. Run it. Change it.", "It stays yours."], cls: ["md", "tag"], mode: "rise", inF: 15, stagger: 8 },
  },
  {
    beats: 8, still: true, trans: "wipeup", pre: async (c) => { await c.load("/trial"); await c.scroll(540); },
    scrim: SHOW,
    calls: [{ sel: ".matrix", shape: "bracket", label: "A WORKSPACE OF YOUR OWN", side: "below", at: [1.4, 3.8] }],
  },
  {
    beats: 8, still: true, trans: null, scrim: STORY([8, 6]), dolly: [1.03, 1.0],
    big: { lines: ["Ask, and a person reads it.",
      "Approval is not automatic, because an account here can scan."],
      cls: ["md", "tag"], mode: "rise", inF: 16, stagger: 9 },
  },
  {
    /* The honest half. A free tool that hides this is selling something. */
    beats: 8, still: true, trans: null, scrim: STORY([8, 6]), dolly: [1.0, 1.03],
    big: { lines: ["No service-level agreement.", "Nobody is on call."], cls: ["md", "md"], mode: "rise", inF: 15, stagger: 8 },
  },
  {
    beats: 8, still: true, trans: null, scrim: STORY([7, 5]), dolly: [1.03, 1.0],
    big: { lines: ["If that will not do, run your own copy.",
      "That is what the licence is for."],
      cls: ["md", "tag"], mode: "rise", inF: 16, stagger: 9 },
  },
  {
    beats: 12, trans: "fade", pre: async (c) => { await c.nav("overview"); await c.scroll(0); },
    dolly: [1.0, 1.03], scrim: { level: 0.76, blur: [5, 5] },
    card: { kick: "Morrow", big: "Cryptographic\ngovernance.", ruleW: 470,
      sub: "For the post-quantum migration.", scrim: null },
  },
  {
    beats: 12, trans: "fade", scrim: { level: 0.78, blur: [5, 5] }, dolly: [1.03, 1.0],
    /* No address: inventing one, even under a reserved TLD, would be the single
       claim in the film that nothing on screen supports. */
    big: { lines: ["Free. Open source. MIT.",
      "Start with one domain.",
      "Example Financial Group is a fictional estate."],
      cls: ["md", "tag", "tag"], mode: "rise", inF: 18, stagger: 10, outF: 60 },
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
  if (beats !== 360) console.log(`  ! ${beats} beats is not the 360 the score is written to`);
  for (let i = 0; i < SHOTS.length; i++) {
    if (SHOTS[i].reveal && SHOTS[i].dolly) {
      console.log(`  ! shot ${i} both turns a chart and dollies — that is the orbit this film does not do`);
    }
  }

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
  /* Reduced motion, so the console's own animations land on their final state.
     Its KPI count-up (static/console-motion.js) times itself by comparing the
     animation frame's timestamp with performance.now(); under the renderer's
     virtual clock those disagree, and frames caught "-2 assets", "$-0.19M" and on
     the board "-1.1e+21". The console already shows the final number when reduced
     motion is set, which is also what this film wants: nothing in the product
     moving behind the words. The overlay is driven by frame number and is not
     affected. */
  await page.emulateMedia({ reducedMotion: "reduce" });
  const clock = K.makeClock(cdp);

  /* The constellation field is stopped through the product's own control. It is
     the only thing on the page that drifts in loops, and the user asked for it
     to go. Everything else the console animates keeps running. */
  const stopField = () => page.evaluate(() => {
    try { window.airlockFabric.setRunning(false); } catch (e) { /* not mounted */ }
    try { window.__ov.vignette(1); } catch (e) { /* not mounted */ }
  }).catch(() => {});

  const c = {
    page, clock,
    scroll: (y) => K.scrollTo(page, y),
    async nav(route) {
      /* From a public page (/check, /r/..., /pricing, /trial) there is no console
         navigation to click, and setting location.hash only changes the URL of the
         page already showing -- so the "console" shots after a public page used to
         be captured on that public page. Go back to the console first. */
      const inConsole = await page.evaluate(() => !!document.querySelector("#nav")).catch(() => false);
      if (!inConsole) await this.load("/ui/#" + route);
      await K.insist("nav " + route, () => page.evaluate((r) => {
        const b = document.querySelector(`#nav button.nav[data-go="${r}"]`);
        if (b) b.click(); else location.hash = "#" + r;
      }, route), 12000).catch(() => {});
      await clock.run(400);
      await K.settled(page, clock);
      await K.scrollTo(page, 0);
      await clock.run(600);
      await stopField();
    },
    async tab(label) {
      const ok = await K.insist("tab " + label, () => page.evaluate((t) => {
        for (const b of document.querySelectorAll(".tabs button")) {
          if ((b.textContent || "").trim() === t) { b.click(); return true; }
        }
        return false;
      }, label), 12000).catch(() => false);
      if (!ok) console.log(`    (no tab "${label}")`);
      await clock.run(500);
      await K.settled(page, clock);
      await clock.run(400);
    },
    async load(url) {
      let landed = false;
      const nav = page.goto(K.BASE + url, { waitUntil: "domcontentloaded" })
        .catch((e) => console.log("  goto", e.message)).then(() => { landed = true; });
      for (let i = 0; i < 70 && !landed; i++) { await clock.free(250); await page.waitForTimeout(80); }
      await nav;
      await clock.free(400);
      await page.waitForTimeout(250);
      await clock.take();
      await page.evaluate(() => window.__ov && window.__ov.mount());
      await K.settled(page, clock, 30000);
      await K.scrollTo(page, 0);
      await clock.run(600);
      await stopField();
    },
    async hover(sel, fx, fy) {
      const b = await page.locator(sel).first().boundingBox().catch(() => null);
      if (!b) { console.log("    (no " + sel + ")"); return; }
      await page.mouse.move(b.x + b.width * fx - 30, b.y + b.height * fy - 20, { steps: 3 });
      await page.mouse.move(b.x + b.width * fx, b.y + b.height * fy, { steps: 6 });
      await clock.run(400);
    },
  };

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
  await page.mouse.move(1905, 1058, { steps: 3 });
  await stopField();
  // Warm the backdrop-blur shader: the first blurred frame in a process costs
  // about a second while it compiles, and it should not be a delivered one.
  await page.evaluate(() => window.__ov.begin({ dur: 4, items: [
    { k: "scrim", a: 0, b: 4, level: 0.5, blur: 9, inF: 1, outF: 1 }] }));
  for (let f = 0; f < 3; f++) {
    await page.evaluate((k) => window.__ov.step(k, 0, 0), f);
    await clock.frame();
    await K.shoot(cdp, BASE_Z, 0, 0, 0, 0);
  }
  await page.evaluate(() => window.__ov.clear());

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
    await stopField();

    const readFact = (v) => K.insist("verify", () => page.evaluate((q) => {
      let e = null;
      if (q.text) { for (const x of document.querySelectorAll(q.sel)) if ((x.textContent || "").includes(q.text)) { e = x; break; } }
      else e = document.querySelectorAll(q.sel)[q.nth || 0];
      return e ? (e.textContent || "").replace(/\s+/g, " ").trim().slice(0, 6000) : null;
    }, v), 12000).catch(() => null);
    for (const v of (s.verify || [])) {
      let got = await readFact(v);
      if (!got || !got.includes(v.has)) { await clock.run(1600); got = await readFact(v); }
      if (!got || !got.includes(v.has)) {
        console.log(`  VERIFY FAIL shot ${i}: "${v.has}" not on screen — read ${JSON.stringify((got || "").slice(0, 90))}`);
      }
    }

    const F = (sec) => Math.round(sec * FPS);
    const items = [];
    if (!prevShot && s.trans && i > 0) prevShot = lastFrameOf(path.join(SEG, String(i - 1).padStart(3, "0") + ".mp4"));
    const transF = (s.trans && prevShot) ? 20 : 0;
    if (transF) items.push({ k: "trans", a: 0, b: transF, kind: s.trans });
    if (s.scrim) items.push({ k: "scrim", a: 0, b: n, level: s.scrim.level, grad: s.scrim.grad,
      blur: s.scrim.blur, blurA: s.scrim.blurA, blurB: s.scrim.blurB, inF: 1, outF: 1 });
    if (s.card) items.push({ k: "card", a: transF, b: n, kick: s.card.kick, big: s.card.big,
      sub: s.card.sub, ruleW: s.card.ruleW,
      scrim: Object.prototype.hasOwnProperty.call(s.card, "scrim") ? s.card.scrim : 0.9,
      inF: 34, outF: 2 });
    if (s.big) items.push({ k: "big", a: transF + 2, b: n + (s.big.outF || 10), lines: s.big.lines,
      cls: s.big.cls, mode: s.big.mode, inF: s.big.inF, stagger: s.big.stagger, outF: s.big.outF || 10,
      justify: s.big.justify || (s.pos === "low" ? "flex-end" : "center"), align: "left" });
    for (const call of (s.calls || [])) {
      const r = await K.insist("callout rect", () => page.evaluate(
        (q) => window.__ov.rect(q.sel, { text: q.text, nth: q.nth }), call), 12000).catch(() => null);
      if (!r) { console.log(`    (no callout target ${call.sel})`); continue; }
      items.push({ k: "call", a: F(call.at[0]), b: Math.min(n, F(call.at[1])), sel: call.sel,
        text: call.text, nth: call.nth, shape: call.shape || "box", label: call.label,
        side: call.side, tone: call.tone, rect: r, drawF: 20, chipDelay: 9 });
    }
    for (const cu of (s.counts || [])) items.push({ k: "count", a: F(cu.at[0]), b: F(cu.at[1]), sel: cu.sel, nth: cu.nth });
    await K.insist("overlay begin", () => page.evaluate(
      // The guard the type must stay inside: the crop's far edge (MX + half the
      // base crop) plus the 128 px frame guard, expressed before the crop's own
      // magnification. Anything closer to the edge than this gets cut off by a
      // truck that has travelled to the other end of its margin.
      (p) => window.__ov.begin(p), {
        dur: n, parallax: 1, items,
        inset: [Math.round(MX + (K.W - K.W / BASE_Z) / 2 + 128 / BASE_Z),
          Math.round(MY + (K.H - K.H / BASE_Z) / 2 + 120 / BASE_Z)],
      }), 15000);

    /* ------------------------------------------------ the camera, in straight
       lines only. The truck crosses the reserved margin on a diagonal whose
       direction alternates; the dolly is linear in scale. */
    const sign = (i % 2 === 0) ? 1 : -1;
    const flip = (Math.floor(i / 2) % 2 === 0) ? 1 : -1;
    const tk = s.truckScale == null ? 1 : s.truckScale;
    const x0 = -MX * sign * tk, x1 = MX * sign * tk;
    const y0 = -MY * flip * tk, y1 = MY * flip * tk;
    const dolly = s.dolly || [1.0, 1.0];
    const zoomOf = [], truckOf = [], scrollOf = [], yawOf = [];
    if (s.still) await clock.release();   // nothing on this page animates; see clock.release
    for (let f = 0; f < n; f++) {
      const t = n === 1 ? 0 : f / (n - 1);
      zoomOf.push(dolly[0] + (dolly[1] - dolly[0]) * t);
      truckOf.push([x0 + (x1 - x0) * t, y0 + (y1 - y0) * t]);
    }
    const perFrame = Math.hypot((x1 - x0) / Math.max(1, n - 1), (y1 - y0) / Math.max(1, n - 1));
    if (perFrame < 0.45 && !s.motion && !s.reveal) {
      console.log(`    ! truck is only ${perFrame.toFixed(3)} px/frame; frames may repeat`);
    }

    if (s.motion && s.motion.kind === "scroll") {
      const m = s.motion;
      const from = await K.insist("scrollY", () => page.evaluate(() => Math.round(window.scrollY * 2) / 2), 12000);
      const cap = await K.insist("maxScroll", () => K.maxScroll(page), 12000);
      const to = Math.min(m.to, cap);
      const dist = Math.abs(to - from), sgn = to >= from ? 1 : -1;
      const e = Math.round(0.3 * FPS);
      const step = Math.max(0.5, Math.round((dist / Math.max(1, Math.round(m.secs * FPS) - e)) * 2) / 2);
      const nm = Math.min(n, Math.max(1, Math.round(dist / step) - e) + 2 * e);
      const r = K.ramp(nm, e);
      const lead = Math.min(Math.round((m.lead != null ? m.lead : 0.3) * FPS), Math.max(0, n - nm));
      for (let f = 0; f < n; f++) {
        const j = f - lead;
        scrollOf.push(Math.round((from + sgn * dist * (j < 0 ? 0 : j >= nm ? 1 : r[j])) * 2 + 1e-6) / 2);
      }
      console.log(`    scroll ${from}->${to} over ${nm}f`);
    }
    if (s.reveal) {
      const o = s.reveal;
      const nm = Math.min(n, Math.round(o.secs * FPS));
      const lead = Math.min(Math.round((o.lead || 0.4) * FPS), Math.max(0, n - nm));
      const r = K.ramp(nm, Math.round(0.45 * FPS));
      for (let f = 0; f < n; f++) {
        const j = f - lead;
        yawOf.push(o.yaw[0] + (o.yaw[1] - o.yaw[0]) * (j < 0 ? 0 : j >= nm ? 1 : r[j]));
      }
      console.log(`    reveal ${o.key} ${o.yaw[0]} -> ${o.yaw[1]} over ${nm}f, then held`);
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
        }, { key: s.reveal.key, yaw: yawOf[f] }), 12000);
      }
      const [dx, dy] = truckOf[f];
      // Parallax, biased so it is never negative: the type drifts inward from
      // its layout position by up to 40 px rather than swinging either side of
      // it, which pushed the first character off the left guard.
      const pdx = ((dx + MX) / (2 * MX)) * 40;
      const pdy = ((dy + MY) / (2 * MY)) * 22;
      const sc = await K.insist("overlay step", () => page.evaluate(
        (a) => { window.__ov.step(a.f, a.dx, a.dy); return { x: window.scrollX, y: window.scrollY }; },
        { f, dx: pdx, dy: pdy }), 12000);
      /* A public page animates nothing once c.load stops the constellation field,
         clock.frame() waits for a frame that never comes and the renderer stops
         answering captureScreenshot -- which is what wedged the first pass on
         /r/{domain}, a page that deliberately ships no JavaScript. Those shots
         let virtual time advance instead of pausing on frames: nothing on the
         page is animating, so frame pacing buys nothing, and the overlay is
         driven by explicit step(f) calls rather than by the clock. */
      if (!s.still) await clock.frame();
      const zoom = zoomOf[f] * BASE_Z;
      try {
        last = await K.shoot(cdp, zoom, sc.x, sc.y, dx, dy);
      } catch (e) {
        console.log("    (screenshot stalled at frame " + f + "; ticking and retrying)");
        if (!s.still) await clock.frame();
        last = await K.shoot(cdp, zoom, sc.x, sc.y, dx, dy);
      }
      await enc.write(last);
    }
    await enc.close();
    if (s.still) await clock.take();   // re-pin for the next shot, which may animate
    if (yawOf.length) await page.evaluate(() => { window.__demoPose = null; try { document.fonts.dispatchEvent(new Event("loadingdone")); } catch (e) {} });
    await K.insist("overlay clear", () => page.evaluate(() => window.__ov.clear()), 12000).catch(() => {});
    prevShot = "data:image/jpeg;base64," + last.toString("base64");
    console.log(`${String(i + 1).padStart(2, "0")}/${SHOTS.length}  ${s.beats}b ${(n / FPS).toFixed(2)}s  ` +
      `${((Date.now() - t0) / 1000).toFixed(0)}s  truck ${perFrame.toFixed(2)}px/f  ` +
      `${(s.big ? K.stripTags(s.big.lines[0]) : (s.card ? s.card.kick : "")).slice(0, 40)}`);
  }

  fs.writeFileSync(path.join(WORK, "film.json"),
    JSON.stringify({ fps: FPS, beat: BEAT, bpm: 120, width: K.W, height: K.H, shots: manifest }, null, 2));
  await page.close(); await browser.close();
  console.log(external.size ? "EXTERNAL REQUESTS:\n" + [...external].join("\n") : "no external requests");
  console.log("segments in", SEG);
})().catch((e) => { console.error("FAIL", e); process.exit(1); });
