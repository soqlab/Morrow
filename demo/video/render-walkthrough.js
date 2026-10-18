/**
 * Renders the Morrow product walkthrough, deterministically.
 *
 * Nothing here is captured in real time. The page is driven to a known state,
 * the product's ambient motion is switched off, and every frame of every
 * moving shot is produced one at a time by stepping the page (scroll offset,
 * chart pose) and taking a full-resolution screenshot. A frame therefore costs
 * the same whatever else the machine is doing, and 60 frames really are one
 * second of picture.
 *
 *   set NODE_PATH=.tools\video\node_modules
 *   node demo\video\render-walkthrough.js [--only 0-5] [--work DIR]
 *
 * Output: <work>/seg/NNN.mp4     one silent 60 fps segment per caption
 *         <work>/shots.json      the manifest assemble-walkthrough.py reads
 *
 * assemble-walkthrough.py then cross-fades the segments together, burns the
 * subtitles and lays the music under it.
 */
const fs = require("fs");
const path = require("path");
const os = require("os");
const { execFileSync } = require("child_process");
const { chromium } = require("playwright");

const REPO = path.resolve(__dirname, "..", "..");
const FFMPEG = path.join(REPO, ".tools", "ffmpeg", "ffmpeg.exe");
const BASE = process.env.PQC_DEMO_BASE || "http://127.0.0.1:8049";
const EMAIL = "avery.chen@example.com";
const PASSWORD = "Airlock-Demo-Recording-8049";
const FPS = 60;
const W = 1920, H = 1080;

const argv = process.argv.slice(2);
const argOf = (name, dflt) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : dflt; };
const WORK = path.resolve(argOf("--work", path.join(os.tmpdir(), "airlock-walkthrough")));
const ONLY = argOf("--only", null);   // "3" or "10-18": re-render part of the tour

const SEG = path.join(WORK, "seg");
const TMP = path.join(WORK, "tmp");

// ------------------------------------------------------------------ page kit
/** Installed before any page script. Two hooks, neither of which changes what
 *  the product draws:
 *   __demoPose    forces the projection pose of one named 3D chart, so a
 *                 rotation can be stepped exactly instead of eased towards a
 *                 drag target at whatever rate the machine manages.
 *   __demoRedraw3d  asks every mounted chart for exactly one more frame. */
const HOOKS = () => {
  window.__demoPose = null;
  window.__demoInstallPose = () => {
    const S = window.airlockSpace;
    if (!S) return false;
    if (S.__demoPatched) return true;
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
  };
  // charts3d redraws every mounted chart on this event (it is how a chart is
  // redrawn once its web font arrives). One event, one frame, no animation.
  window.__demoRedraw3d = () => { try { document.fonts.dispatchEvent(new Event("loadingdone")); } catch (e) {} };
  // The console repolls some panels (the overview risk panels every 20s, the
  // support-session log every 1.5s). A shot's frames take minutes of wall clock
  // to render, so a repoll would land in the middle of one. Interval callbacks
  // are skipped while a shot is being captured and run normally in between.
  window.__demoFrozen = false;
  const origSI = window.setInterval;
  window.setInterval = function (fn, ms) {
    if (typeof fn !== "function") return origSI.apply(window, arguments);
    const rest = Array.prototype.slice.call(arguments, 2);
    const wrapped = function () { if (window.__demoFrozen) return; return fn.apply(this, arguments); };
    return origSI.apply(window, [wrapped, ms].concat(rest));
  };
  // A push-in is a real re-render at a new scale, not a resample of a still:
  // Chrome rasterises the page at the composited scale, so a 2% move over six
  // seconds advances by a fraction of a pixel a frame with nothing to step on.
  window.__demoScale = (k) => {
    const r = document.documentElement;
    if (k === 1) { r.style.transform = ""; r.style.transformOrigin = ""; r.style.overflow = ""; return; }
    r.style.transformOrigin = "50% 50%";
    r.style.overflow = "hidden";
    r.style.transform = "scale(" + k + ")";
  };
};

// ------------------------------------------------------------------ helpers
const sleep = (p, ms) => p.waitForTimeout(ms);
const raf2 = (p) => p.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));

/** Wait until the view has painted: children present, skeletons gone, height
 *  settled over two consecutive polls. Generous, because nothing here is being
 *  recorded while it waits. */
async function settled(p, cap = 25000) {
  const t0 = Date.now();
  let lastH = -1, stable = 0;
  while (Date.now() - t0 < cap) {
    const s = await p.evaluate(() => {
      const v = document.querySelector("#view");
      return {
        kids: v ? v.children.length : 0,
        sk: document.querySelectorAll(".sk").length,
        h: document.documentElement.scrollHeight,
        imgs: [...document.images].every((i) => i.complete),
      };
    }).catch(() => null);
    if (s && s.kids >= 2 && s.sk === 0 && s.imgs && s.h === lastH) {
      if (++stable >= 3) return true;
    } else stable = 0;
    if (s) lastH = s.h;
    await p.waitForTimeout(250);
  }
  console.log("    (settle timed out)");
  return false;
}

async function nav(p, route) {
  await p.evaluate(() => {
    const first = document.querySelector("#view") && document.querySelector("#view").firstElementChild;
    if (first) first.setAttribute("data-demo-outgoing", "1");
  }).catch(() => {});
  const btn = p.locator(`#nav button.nav[data-go="${route}"]`).first();
  if (await btn.count()) await btn.click();
  else await p.evaluate((r) => { location.hash = r; }, "#" + route);
  await p.waitForFunction(() => !document.querySelector("#view [data-demo-outgoing]"), null, { timeout: 15000 }).catch(() => {});
  await settled(p);
  await scrollTo(p, 0);
  await sleep(p, 1200);
}

async function tab(p, label) {
  const loc = p.locator(`.tabs button:has-text("${label}")`).first();
  try { await loc.waitFor({ state: "visible", timeout: 10000 }); }
  catch { console.log(`    (no tab "${label}")`); return false; }
  await loc.click({ timeout: 10000 }).catch((e) => console.log("    tab click failed", e.message));
  await sleep(p, 900);
  await settled(p);
  await sleep(p, 900);
  return true;
}

async function load(p, url) {
  await p.goto(url, { waitUntil: "domcontentloaded" });
  await p.waitForLoadState("networkidle", { timeout: 25000 }).catch(() => {});
  await sleep(p, 2500);
  await settled(p);
  await scrollTo(p, 0);
  await sleep(p, 1200);
}

const scrollTo = (p, y) => p.evaluate((t) => {
  const max = Math.max(0, document.documentElement.scrollHeight - window.innerHeight);
  window.scrollTo({ top: Math.max(0, Math.min(t, max)), left: 0, behavior: "instant" });
}, y);

const maxScroll = (p) => p.evaluate(() => Math.max(0, document.documentElement.scrollHeight - window.innerHeight));

async function hoverCanvas(p, sel, fx, fy) {
  const loc = p.locator(sel).first();
  if (!(await loc.count())) { console.log("    (no canvas " + sel + ")"); return false; }
  const b = await loc.boundingBox().catch(() => null);
  if (!b) return false;
  const x = b.x + b.width * fx, y = b.y + b.height * fy;
  await p.mouse.move(x - 40, y - 30, { steps: 6 });
  await p.mouse.move(x, y, { steps: 12 });
  await sleep(p, 700);
  return true;
}
const park = (p) => p.mouse.move(1905, 1058, { steps: 4 });

// ------------------------------------------------------------------ the tour
// One entry per caption. `pad` is deliberate extra silence; `fade` marks a cut
// the assembler should cross-dissolve into (a new page, a new tab, a jump in
// scroll position). `pre` puts the page where the shot starts; `motion`
// describes what moves while the caption is up.
//
//   hold                       the frame is still; the cross-dissolves and the
//                              page's own state changes carry the picture
//   hold + push                a slow constant-velocity push-in over a 2x still
//   scroll {to, secs, lead}    the scroll offset is stepped once per frame
//   rotate {key, yaw, secs}    a 3D chart's pose is stepped once per frame
//
// Scroll ceilings on two views are deliberate; see the note above each.
const SHOTS = [
  // --- 0. opening -------------------------------------------------------
  { cap: ["Morrow"], pad: 2, fade: true,
    pre: async (p) => { await nav(p, "overview"); }, push: 0.028 },
  { cap: ["A cryptographic governance platform", "for the post-quantum migration."] },
  { cap: ["Recorded against a live build", "and a fictional customer estate."], pad: 1 },

  // --- 1. the problem ---------------------------------------------------
  { cap: ["Traffic your organisation encrypts today", "can be recorded today."], pad: 1, fade: true },
  { cap: ["It becomes readable later, once a quantum computer", "can break RSA and elliptic-curve cryptography."], pad: 1.5, push: 0.022 },
  { cap: ["So data with a long secrecy requirement", "is already exposed, though nothing has been broken yet."], pad: 1.5, fade: true },
  { cap: ["The company here is Example Financial Group —", "an invented bank with thirty-eight endpoints."],
    motion: { kind: "scroll", to: 300, secs: 3.4 } },
  { cap: ["The console opens on posture: inventory, open fixes,", "modelled exposure and crypto-agility."], pad: 1,
    motion: { kind: "scroll", to: 640, secs: 4.0 } },
  { cap: ["And the deadlines are not hypothetical.", "CNSA 2.0, NSM-10 and NIST guidance carry published dates."],
    fade: true, pre: async (p) => { await nav(p, "qday"); } },
  { cap: ["Optimistic, median and conservative scenarios —", "not one confident date."],
    motion: { kind: "scroll", to: 360, secs: 3.4 } },
  // Scrolls on this view stay at or below 1150px: the Quantum intelligence feed
  // below that point lists published hardware milestones by the organisation
  // that announced them, and this recording names no real third party.
  { cap: ["Some target dates have already passed.", "Others land in 2030 and 2033."],
    motion: { kind: "scroll", to: 980, secs: 5.0 } },
  { cap: ["The platform models when a relevant quantum computer", "becomes credible — and labels it as a model."], pad: 1.5,
    motion: { kind: "scroll", to: 1150, secs: 2.6 } },

  // --- 2. discovery -----------------------------------------------------
  { cap: ["Discovery."], pad: 1, fade: true, push: 0.026,
    pre: async (p) => { await nav(p, "scans"); } },
  { cap: ["Everything downstream starts with what you actually run,", "not what the documentation says you run."], pad: 1 },
  { cap: ["Morrow scans TLS endpoints and records", "what each one really negotiated."],
    motion: { kind: "scroll", to: 440, secs: 3.6 } },
  { cap: ["Protocol version, cipher suite, key algorithm,", "key size, and the certificate chain behind it."],
    motion: { kind: "scroll", to: 680, secs: 4.0 } },
  // 907 is the bottom of this view; the scan history sits there.
  { cap: ["Eight scan runs over five months, so the history", "has shape rather than being one snapshot."],
    motion: { kind: "scroll", to: 907, secs: 4.0 } },
  { cap: ["The inventory it builds."], fade: true, push: 0.02,
    pre: async (p) => { await nav(p, "assets"); } },
  { cap: ["Each endpoint becomes an asset with an owner, a team,", "an environment and a data-confidentiality lifetime."], pad: 1,
    motion: { kind: "scroll", to: 260, secs: 2.8 } },
  { cap: ["RSA 2048 and 3072. Elliptic curve P-256 and P-384.", "One gateway already negotiating a hybrid key exchange."],
    motion: { kind: "scroll", to: 560, secs: 3.4 } },
  { cap: ["Confidentiality lifetime is the field that matters most —", "how long this data has to stay secret."],
    motion: { kind: "scroll", to: 1100, secs: 4.8 } },
  { cap: ["Ownership is what turns a cryptographic finding", "into work a named team can be asked to do."], pad: 1.5,
    motion: { kind: "scroll", to: 1560, secs: 4.4 } },

  // --- 3. exposure ------------------------------------------------------
  { cap: ["Exposure."], fade: true, push: 0.026,
    pre: async (p) => { await nav(p, "hndl"); } },
  { cap: ["Harvest now, decrypt later. The question is not", "whether an endpoint is weak today."], pad: 0.5 },
  { cap: ["It is what an adversary could store today", "and read after Q-Day."], pad: 1, push: 0.02 },
  { cap: ["So each asset is priced: what the traffic is worth,", "how long it stays secret, the odds it is broken by then."], pad: 1,
    motion: { kind: "scroll", to: 240, secs: 2.6 } },
  { cap: ["Exposure grouped by algorithm class.", "RSA-2048 carries most of it."], fade: true,
    pre: async (p) => { await scrollTo(p, 240); await hoverCanvas(p, ".c3d[data-c3d='bar'] canvas", 0.22, 0.55); } },
  { cap: ["The priority queue is ranked by modelled exposure,", "not by a severity label."], fade: true,
    pre: async (p) => { await park(p); },
    motion: { kind: "scroll", to: 470, secs: 3.0 } },
  { cap: ["Owner, environment, algorithm, probability broken,", "data category, and how long it has been harvestable."],
    motion: { kind: "scroll", to: 640, secs: 2.6 } },
  // 820 puts both 3D charts in frame and keeps the Adversary landscape row
  // (whose quantum threat model card cites a published milestone by name)
  // below the fold. Do not scroll past it on this view.
  { cap: ["Then the exposure timeline."],
    motion: { kind: "scroll", to: 820, secs: 3.0 } },
  { cap: ["It is a real three-dimensional chart. You can turn it."],
    motion: { kind: "rotate", key: "timeline", from: -0.18, to: 0.46, secs: 3.0, hold: 0.5, back: true } },
  { cap: ["Amber is traffic captured but still sealed."], fade: true,
    pre: async (p) => { await hoverCanvas(p, ".c3d[data-c3d='timeline'] canvas", 0.30, 0.62); } },
  { cap: ["Red is the same traffic, readable,", "once the model's Q-Day wall is crossed."], fade: true,
    pre: async (p) => { await hoverCanvas(p, ".c3d[data-c3d='timeline'] canvas", 0.78, 0.55); } },
  { cap: ["Beside it, the probability ribbons: one curve per algorithm,", "with the year each reaches a fifty per cent chance."], fade: true,
    pre: async (p) => { await hoverCanvas(p, ".c3d[data-c3d='curves'] canvas", 0.55, 0.45); } },
  { cap: ["Every modelled figure carries a badge saying it is a model,", "with the date, the sources and the assumptions."], pad: 1, fade: true,
    pre: async (p) => { await park(p); },
    motion: { kind: "scroll", to: 470, secs: 3.2 } },
  { cap: ["Nothing here is presented as measurement", "when it is an estimate."], pad: 1.5 },

  // --- 4. evidence ------------------------------------------------------
  { cap: ["Evidence."], fade: true, push: 0.026,
    pre: async (p) => { await nav(p, "cbom"); } },
  { cap: ["Exposure is an argument.", "Evidence is what an auditor actually reads."], pad: 1 },
  { cap: ["The cryptographic bill of materials is generated", "from the scans themselves, in CycloneDX 1.6."], pad: 0.5,
    motion: { kind: "scroll", to: 150, secs: 2.4 } },
  { cap: ["Every protocol, certificate and algorithm found,", "each with its quantum status."],
    motion: { kind: "scroll", to: 290, secs: 3.0 } },
  // 407 is the bottom of this view.
  { cap: ["Eighty-seven components in this estate.", "Two of them are already post-quantum."],
    motion: { kind: "scroll", to: 407, secs: 3.0 } },
  { cap: ["Downloadable as JSON or CSV, so it can leave", "the product and still mean something."],
    motion: { kind: "scroll", to: 0, secs: 4.6 } },
  // Compliance, Evidence, Board & ROI and the Administration panels each fit a
  // single screen, so those shots are holds: the dissolve into them is the move.
  { cap: ["Then the mapping to control frameworks.", "It is honest: this estate scores badly, and it says so."], fade: true,
    pre: async (p) => { await nav(p, "governance"); await tab(p, "Compliance"); } },
  { cap: ["Evidence packs collect the control artefacts", "with timestamps and a hash chain."], pad: 2, fade: true,
    pre: async (p) => { await scrollTo(p, 0); await tab(p, "Evidence"); } },
  // Deliberately not clicking "Build evidence pack": the pack is a ZIP and the
  // Generated evidence panel prints its bytes, which fills half the screen with
  // mojibake. The frameworks list makes the point without it.

  // --- 5. action --------------------------------------------------------
  { cap: ["Action."], fade: true, push: 0.026,
    pre: async (p) => { await nav(p, "remediation"); } },
  { cap: ["Finding cryptography is the easy part.", "Changing it is the work."], pad: 1 },
  { cap: ["Every fix moves through suggested, approved,", "pull request, and verified closed."],
    motion: { kind: "scroll", to: 420, secs: 3.4 } },
  { cap: ["Two are closed and verified against a later scan.", "Seven are still open."], pad: 1,
    motion: { kind: "scroll", to: 620, secs: 2.6 } },
  { cap: ["Open one and it carries the file,", "the current configuration, and the proposed change."], fade: true,
    pre: async (p) => {
      const b = p.locator('#view table button:has-text("Open")').first();
      if (await b.count()) { await b.click().catch(() => {}); await sleep(p, 2200); await settled(p, 12000); }
      else console.log("    (no Open button)");
      await park(p);
    } },
  { cap: ["Approve, reject, validate, open a pull request, mark merged —", "every step is recorded against the asset."],
    motion: { kind: "scroll", to: 320, secs: 3.0 } },
  { cap: ["Before you change a certificate authority,", "you want to know what depends on it."], fade: true,
    pre: async (p) => { await p.keyboard.press("Escape").catch(() => {}); await sleep(p, 900); await nav(p, "graph"); } },
  { cap: ["Blast radius: assets, repositories and fixes", "in one graph you can interrogate."],
    motion: { kind: "scroll", to: 330, secs: 3.0 } },
  { cap: ["Two roots and two issuing authorities sit", "under thirty-eight leaf certificates here."], fade: true,
    pre: async (p) => { await scrollTo(p, 0); await tab(p, "Certificate blast radius"); },
    motion: { kind: "scroll", to: 330, secs: 3.0, lead: 1.8 } },
  { cap: ["If that public root failed, fifty-five dependent nodes", "would be affected, and the model prices it."], pad: 1.5,
    motion: { kind: "scroll", to: 560, secs: 3.0 } },
  { cap: ["And a tripwire ladder: five canary keys at five strengths.", "Each only breaks if that algorithm breaks."], fade: true,
    pre: async (p) => { await nav(p, "canaries"); },
    motion: { kind: "scroll", to: 420, secs: 3.4, lead: 1.4 } },
  { cap: ["So the first one to trip tells you", "how far quantum capability has actually reached."], pad: 1.5 },

  // --- 6. governance ----------------------------------------------------
  { cap: ["Governance."], fade: true, push: 0.026,
    pre: async (p) => { await nav(p, "board"); } },
  { cap: ["For the board, one composite score —", "with every weight shown."], pad: 0.5 },
  { cap: ["Inventory coverage, open exposure reduction,", "crypto-agility, blocker control."], pad: 0.5,
    motion: { kind: "rotate", key: "gauge", from: -0.26, to: 0.30, secs: 2.6, hold: 0.4, back: true } },
  { cap: ["Components with no evidence behind them are marked", "not measured, rather than scored from nothing."], pad: 1, fade: true,
    pre: async (p) => { await park(p); } },
  { cap: ["Regulatory exposure is listed by regime,", "with the alignment state the evidence supports."], pad: 1 },
  { cap: ["The executive view is the same view the engineers", "work in. There is no second set of numbers."], pad: 1.5, fade: true,
    pre: async (p) => { await nav(p, "overview"); },
    motion: { kind: "scroll", to: 340, secs: 3.4, lead: 1.6 } },

  // --- 7. for the buyer's security team ---------------------------------
  { cap: ["If you are the security team buying this,", "four things matter."], fade: true,
    pre: async (p) => { await nav(p, "admin"); } },
  { cap: ["One: tenant isolation is enforced in the database,", "not only in application code."], fade: true,
    pre: async (p) => { await tab(p, "Data & isolation"); } },
  { cap: ["Row-level security, scoped per organisation,", "with a cross-tenant probe you can run yourself."] },
  { cap: ["Two: vendor support cannot look at your workspace silently.", "Read-only, time-limited, with a stated reason."], fade: true,
    pre: async (p) => { await scrollTo(p, 0); await tab(p, "Support access"); } },
  { cap: ["Three: the audit trail is hash-chained,", "so a removed entry is detectable."], fade: true,
    pre: async (p) => { await scrollTo(p, 0); await tab(p, "Audit trail"); },
    motion: { kind: "scroll", to: 300, secs: 3.0, lead: 2.0 } },
  { cap: ["Four: the operators who run the platform sign in", "through an identity provider, with authenticator MFA."], fade: true,
    pre: async (p) => { await load(p, BASE + "/enterprise-admin"); } },
  { cap: ["Destructive actions ask for a fresh code.", "The shared key is an emergency credential only."],
    motion: { kind: "scroll", to: 760, secs: 4.0 } },
  { cap: ["And the data boundary is explicit about what", "is allowed to leave your environment."], fade: true,
    pre: async (p) => { await load(p, BASE + "/data-boundary"); },
    motion: { kind: "scroll", to: 720, secs: 4.0, lead: 1.8 } },
  { cap: ["Cryptographic metadata, fingerprints and workflow records", "may cross. Source code, private keys and tokens do not."], pad: 1.5,
    motion: { kind: "scroll", to: 1180, secs: 4.0 } },

  // --- 8. close ---------------------------------------------------------
  // The old cut reloaded the console here and caught it repopulating. Nothing
  // is captured now until the page has settled, so the reload cannot be seen.
  { cap: ["Where to start."], fade: true, push: 0.026,
    pre: async (p) => { await load(p, BASE + "/ui/#overview"); } },
  { cap: ["A first pilot is deliberately narrow.", "Six to eight weeks. One organisation."], pad: 1 },
  { cap: ["Three to five critical applications,", "and the assets that support them."], pad: 1,
    motion: { kind: "scroll", to: 300, secs: 3.2 } },
  { cap: ["One approved cryptographic inventory.", "One fix carried all the way to verified closure."], pad: 1,
    motion: { kind: "scroll", to: 640, secs: 3.6 } },
  { cap: ["One evidence pack an auditor can read."], pad: 1 },
  { cap: ["Start with the endpoints whose data", "has to stay secret the longest."], pad: 1.5, fade: true,
    pre: async (p) => { await nav(p, "overview"); } },
  { cap: ["Morrow.", "Cryptographic governance for the post-quantum migration."], pad: 3, push: 0.024 },
  { cap: [], pad: 3.5 },
];

// ------------------------------------------------------------------ duration
// Reading time: about 13.5 characters a second plus a beat to settle, which is
// what the old cut used. TARGET then scales every shot uniformly so the
// delivered file lands where it should.
const TARGET = Number(process.env.PQC_TARGET_SECONDS || 640);
function plannedSeconds(s) {
  const chars = (s.cap || []).join(" ").length;
  if (!chars) return (s.pad || 2);
  return Math.max(3.4, chars / 13.5 + 1.9) + (s.pad || 0);
}

// ------------------------------------------------------------------ segments
function ff(args) {
  execFileSync(FFMPEG, ["-y", "-nostdin", "-v", "error", ...args], { stdio: ["ignore", "inherit", "inherit"] });
}
const ENC = ["-c:v", "libx264", "-preset", "medium", "-crf", "16", "-profile:v", "high", "-level", "4.2",
  "-pix_fmt", "yuv420p", "-r", String(FPS), "-g", "120", "-x264-params", "scenecut=0",
  "-colorspace", "bt709", "-color_primaries", "bt709", "-color_trc", "bt709", "-an"];

/** A still, held. */
function segStill(still, frames, out) {
  ff(["-loop", "1", "-framerate", String(FPS), "-i", still, "-vf", "setsar=1", "-frames:v", String(frames), ...ENC, out]);
}

/** A rendered sequence, optionally with still frames cloned onto either end. */
function segSeq(dir, frames, out, lead, tail) {
  const pad = [];
  if (lead > 0) pad.push(`start_mode=clone:start_duration=${(lead / FPS).toFixed(4)}`);
  if (tail > 0) pad.push(`stop_mode=clone:stop_duration=${(tail / FPS).toFixed(4)}`);
  const vf = pad.length ? `tpad=${pad.join(":")},setsar=1` : "setsar=1";
  ff(["-framerate", String(FPS), "-start_number", "0", "-i", path.join(dir, "%05d.png"),
    "-vf", vf, "-frames:v", String(frames), ...ENC, out]);
}

// ------------------------------------------------------------------ capture
/** A progress curve whose middle advances by exactly the same amount every
 *  frame, with a short smooth ease onto and off the move. Returns n values
 *  rising from just above 0 to exactly 1. */
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

async function shoot(p, file, scale) {
  const buf = await p.screenshot({ type: "png", scale: scale || "css", animations: "disabled", caret: "hide" });
  fs.writeFileSync(file, buf);
}

// ------------------------------------------------------------------ main
(async () => {
  fs.mkdirSync(SEG, { recursive: true });
  fs.rmSync(TMP, { recursive: true, force: true });
  fs.mkdirSync(TMP, { recursive: true });

  let lo = 0, hi = SHOTS.length - 1;
  if (ONLY) { const m = /^(\d+)(?:-(\d+))?$/.exec(ONLY); lo = Number(m[1]); hi = m[2] ? Number(m[2]) : lo; }

  const planned = SHOTS.map(plannedSeconds);
  const sum = planned.reduce((a, b) => a + b, 0);
  // Every dissolve adds half a second of its own to the delivered length, so
  // the shots are scaled to leave room for them.
  const fades = SHOTS.filter((x, j) => j > 0 && (x.fade || SHOTS[j - 1].push)).length;
  const k = (TARGET - fades * 0.5) / sum;
  console.log(`${fades} dissolves -> ${(fades * 0.5).toFixed(1)}s`);
  const frames = planned.map((s) => Math.max(60, Math.round(s * k * FPS)));
  console.log(`planned ${sum.toFixed(1)}s -> ${(frames.reduce((a, b) => a + b, 0) / FPS).toFixed(1)}s (x${k.toFixed(4)})`);

  const auth = await (await fetch(`${BASE}/auth/login`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: EMAIL, password: PASSWORD }),
  })).json();

  const browser = await chromium.launch({ channel: "chrome", headless: true });
  const ctx = await browser.newContext({
    viewport: { width: W, height: H },
    deviceScaleFactor: 2,          // stills are captured at 2x so a push-in stays sharp
    reducedMotion: "reduce",       // the product's own ambient motion holds still
    colorScheme: "dark",
  });
  await ctx.addInitScript((a) => {
    localStorage.setItem("pqc_token", a.access_token);
    localStorage.setItem("pqc_refresh", a.refresh_token);
    localStorage.setItem("pqc_theme", "dark");
    localStorage.setItem("airlock-motion-paused", "1");   // body[data-motion="paused"]
  }, auth);
  await ctx.addInitScript(HOOKS);

  const page = await ctx.newPage();
  page.setDefaultTimeout(15000);
  const external = new Set();
  page.on("request", (r) => {
    const u = r.url();
    if (!u.startsWith(BASE) && !/^(data|blob|about):/.test(u)) external.add(u);
  });
  page.on("pageerror", (e) => console.log("  PAGEERR", e.message));

  await page.goto(`${BASE}/ui/#overview`, { waitUntil: "domcontentloaded" });
  await settled(page, 40000);
  await sleep(page, 2000);
  await park(page);

  const manifest = [];
  for (let i = 0; i < SHOTS.length; i++) {
    const s = SHOTS[i];
    const n = frames[i];
    // A push-in ends a couple of per cent in; the next shot starts at 1.0, so it
    // is always dissolved into rather than cut to.
    const fade = !!s.fade || !!(SHOTS[i - 1] && SHOTS[i - 1].push);
    manifest.push({ i, cap: s.cap, frames: n, seconds: n / FPS, fade });
    if (i < lo || i > hi) {
      // Skipped, but the page still has to end where the next shot expects it.
      if (s.pre) await s.pre(page);
      if (s.motion && s.motion.kind === "scroll") await scrollTo(page, s.motion.to);
      continue;
    }

    const t0 = Date.now();
    const out = path.join(SEG, String(i).padStart(3, "0") + ".mp4");
    // Every shot re-establishes its own page state, so a range can be
    // re-rendered on its own. `pre` is never captured.
    if (s.pre) { await s.pre(page); await page.evaluate(() => window.__demoInstallPose()); }
    await raf2(page);

    const m = s.motion;
    const dir = path.join(TMP, "f");
    const fresh = () => { fs.rmSync(dir, { recursive: true, force: true }); fs.mkdirSync(dir, { recursive: true }); };
    await page.evaluate(() => { window.__demoFrozen = true; });

    if (!m && !s.push) {
      const still = path.join(TMP, "still.png");
      await shoot(page, still);
      segStill(still, n, out);

    } else if (s.push) {
      // A slow constant-velocity push-in, rendered by the browser at each scale.
      fresh();
      for (let f = 0; f < n; f++) {
        await page.evaluate((k) => window.__demoScale(k), 1 + s.push * (f / (n - 1)));
        await raf2(page);
        await shoot(page, path.join(dir, String(f).padStart(5, "0") + ".png"));
      }
      await page.evaluate(() => window.__demoScale(1));
      console.log(`    push 1.000 -> ${(1 + s.push).toFixed(3)} over ${n}f`);
      segSeq(dir, n, out, 0, 0);
      fs.rmSync(dir, { recursive: true, force: true });

    } else if (m.kind === "scroll") {
      fresh();
      const from = await page.evaluate(() => Math.round(window.scrollY * 2) / 2);
      const cap = await maxScroll(page);
      const to = Math.min(m.to, cap);
      if (m.to > cap + 2) console.log(`    (scroll ${m.to} clamped to ${cap})`);
      const dist = Math.abs(to - from), sign = to >= from ? 1 : -1;
      const e = Math.round(0.35 * FPS);
      // A whole number of device pixels a frame through the middle of the move,
      // so the step cannot alternate against the half CSS pixel the scroller
      // rounds to. Half a pixel a frame, 30 px a second, is the slowest drift
      // that still advances on every frame.
      const want = Math.max(1, Math.round(m.secs * FPS));
      let step = Math.max(0.5, Math.round((dist / Math.max(1, want - e)) * 2) / 2);
      let flat = Math.max(1, Math.round(dist / step) - e);
      let nm = Math.min(n, flat + 2 * e);
      flat = nm - 2 * e;
      const r = ramp(nm, e);
      const lead = Math.min(Math.round((m.lead != null ? m.lead : 0.7) * FPS), Math.max(0, n - nm));
      const tail = Math.max(0, n - nm - lead);
      let prev = null; const steps = [];
      for (let f = 0; f < nm; f++) {
        // The epsilon keeps a position that lands exactly on a quarter pixel from
        // rounding up or down at the mercy of the last bit of the accumulator.
        const y = Math.round((from + sign * dist * r[f]) * 2 + 1e-6) / 2;
        if (prev !== null) steps.push(Math.abs(y - prev));
        prev = y;
        await scrollTo(page, y);
        await raf2(page);
        await shoot(page, path.join(dir, String(f).padStart(5, "0") + ".png"));
      }
      const mid = steps.slice(e, steps.length - e);
      console.log(`    scroll ${from}->${to} over ${nm}f, flat step ${Math.min(...mid)}-${Math.max(...mid)} px/frame`);
      segSeq(dir, n, out, lead, tail);
      fs.rmSync(dir, { recursive: true, force: true });

    } else if (m.kind === "rotate") {
      fresh();
      await park(page);
      await page.evaluate(() => window.__demoInstallPose());
      const nm = Math.min(n, Math.round(m.secs * FPS));
      const hold = Math.round((m.hold || 0) * FPS);
      const half = m.back ? Math.round((nm - hold) / 2) : nm - hold;
      const backN = m.back ? nm - half - hold : 0;
      const lead = Math.min(Math.round((m.lead != null ? m.lead : 0.5) * FPS), Math.max(0, n - nm));
      const tail = Math.max(0, n - nm - lead);
      const yaws = [];
      const fwd = ramp(half, Math.round(0.3 * FPS));
      for (let f = 0; f < half; f++) yaws.push(m.from + (m.to - m.from) * fwd[f]);
      for (let f = 0; f < hold; f++) yaws.push(m.to);
      if (backN > 0) {
        const rev = ramp(backN, Math.round(0.3 * FPS));
        for (let f = 0; f < backN; f++) yaws.push(m.to + (m.from - m.to) * rev[f]);
      }
      for (let f = 0; f < yaws.length; f++) {
        await page.evaluate((pose) => { window.__demoPose = pose; window.__demoRedraw3d(); },
          { key: m.key, yaw: yaws[f], tilt: m.tilt != null ? m.tilt : null });
        await raf2(page);
        await shoot(page, path.join(dir, String(f).padStart(5, "0") + ".png"));
      }
      await page.evaluate(() => { window.__demoPose = null; window.__demoRedraw3d(); });
      const d = yaws.slice(1).map((v, j) => Math.abs(v - yaws[j]));
      const midd = d.slice(Math.round(half * 0.4), Math.round(half * 0.6));
      console.log(`    rotate ${m.key} ${m.from} -> ${m.to} over ${yaws.length}f, flat step ` +
        `${Math.min(...midd).toFixed(5)}-${Math.max(...midd).toFixed(5)} rad`);
      segSeq(dir, n, out, lead, tail);
      fs.rmSync(dir, { recursive: true, force: true });
    }
    await page.evaluate(() => { window.__demoFrozen = false; });

    console.log(`${String(i + 1).padStart(2, "0")}/${SHOTS.length}  ${(n / FPS).toFixed(2)}s  ${((Date.now() - t0) / 1000).toFixed(0)}s  ${(s.cap[0] || "(clear)").slice(0, 52)}`);
  }

  fs.writeFileSync(path.join(WORK, "shots.json"), JSON.stringify({ fps: FPS, width: W, height: H, target: TARGET, shots: manifest }, null, 2));
  await page.close(); await ctx.close(); await browser.close();
  if (external.size) console.log("EXTERNAL REQUESTS:\n" + [...external].join("\n"));
  else console.log("no external requests");
  console.log("segments in", SEG);
})();
