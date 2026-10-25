/**
 * Records the Morrow product walkthrough.
 *
 * Drives a real Chrome through Playwright against the demo server on 8049,
 * burns a caption bar into the page, records 1920x1080 video, and writes the
 * matching .srt next to it.
 *
 *   set NODE_PATH=.tools\video\node_modules
 *   node demo\video\record-walkthrough.js
 *
 * Output: demo/video/raw/<uuid>.webm  and  demo/video/morrow-walkthrough.srt
 * ffmpeg then turns the webm into the delivered MP4 (see build-walkthrough.ps1).
 */
const fs = require("fs");
const path = require("path");
const { chromium } = require("playwright");

const BASE = process.env.MORROW_DEMO_BASE || "http://127.0.0.1:8049";
const EMAIL = "avery.chen@example.com";
const PASSWORD = "Airlock-Demo-Recording-8049";
const OUT = path.resolve(__dirname);
const RAW = path.join(OUT, "raw");
const PACE = Number(process.env.MORROW_DEMO_PACE || 1);

// ---------------------------------------------------------------- helpers
const wait = (p, ms) => p.waitForTimeout(Math.round(ms * PACE));

async function caption(p, lines) {
  await p.evaluate((ls) => window.__cap(ls), lines);
}

/** Wait until the view has actually painted: content present, skeletons gone.
 *  Capped, so a slow endpoint costs a few seconds rather than stalling the tour. */
async function settled(p, cap = 9000) {
  const t0 = Date.now();
  while (Date.now() - t0 < cap) {
    const ready = await p.evaluate(() => {
      const v = document.querySelector("#view");
      if (!v || v.children.length < 2) return false;
      return v.scrollHeight > 900 && v.querySelectorAll(".sk").length <= 2;
    }).catch(() => false);
    if (ready) return;
    await p.waitForTimeout(300);
  }
}

async function go(p, route, settle = 2200) {
  // Mark the outgoing view. The app replaces #view's children, so waiting for
  // the mark to disappear is what proves the new view has actually painted --
  // settled() alone can be satisfied by the view we are leaving.
  await p.evaluate(() => {
    const first = document.querySelector("#view")?.firstElementChild;
    if (first) first.setAttribute("data-demo-outgoing", "1");
  }).catch(() => {});
  const btn = p.locator(`#nav button.nav[data-go="${route}"]`).first();
  if (await btn.count()) await btn.click();
  else await p.evaluate((r) => { location.hash = r; }, "#" + route);
  await p.waitForFunction(() => !document.querySelector("#view [data-demo-outgoing]"),
    null, { timeout: 12000 }).catch(() => {});
  await settled(p);
  await p.evaluate(() => window.scrollTo({ top: 0, behavior: "auto" }));
  await wait(p, settle);
}

async function smoothScroll(p, y, ms = 2200) {
  await p.evaluate(async ([target, dur]) => {
    const start = window.scrollY;
    const max = document.documentElement.scrollHeight - window.innerHeight;
    const end = Math.max(0, Math.min(target, max));
    const t0 = performance.now();
    await new Promise((done) => {
      const step = (t) => {
        const k = Math.min(1, (t - t0) / dur);
        const e = k < 0.5 ? 2 * k * k : 1 - Math.pow(-2 * k + 2, 2) / 2;
        window.scrollTo(0, start + (end - start) * e);
        k < 1 ? requestAnimationFrame(step) : done();
      };
      requestAnimationFrame(step);
    });
  }, [y, Math.round(ms * PACE)]);
}

async function scrollToSel(p, sel, ms = 2200, offset = 150) {
  const y = await p.evaluate((s) => {
    const el = document.querySelector(s);
    return el ? el.getBoundingClientRect().top + window.scrollY : null;
  }, sel);
  if (y === null) { console.log("  (no element " + sel + ")"); return false; }
  await smoothScroll(p, y - offset, ms);
  return true;
}

async function clickText(p, sel, label) {
  const loc = p.locator(`${sel}:has-text("${label}")`).first();
  // Wait for it rather than giving up: a view can still be painting.
  try { await loc.waitFor({ state: "visible", timeout: 8000 }); }
  catch { console.log(`  (no ${sel} "${label}")`); return false; }
  await loc.scrollIntoViewIfNeeded().catch(() => {});
  await loc.click({ timeout: 8000 }).catch((e) => console.log("  click failed", e.message));
  return true;
}

/** Bounding box of the first match, or null fast when there is none. */
async function boxOf(p, sel) {
  const loc = p.locator(sel).first();
  if (!(await loc.count())) return null;
  return await loc.boundingBox({ timeout: 3000 }).catch(() => null);
}

async function hoverCanvas(p, sel, fx, fy, dwell = 1700) {
  const box = await boxOf(p, sel);
  if (!box) { console.log("  (no canvas " + sel + ")"); return; }
  const x = box.x + box.width * fx, y = box.y + box.height * fy;
  await p.mouse.move(x - 60, y - 40, { steps: 12 });
  await p.mouse.move(x, y, { steps: 22 });
  await wait(p, dwell);
}

async function dragCanvas(p, sel, dx, dy) {
  const box = await boxOf(p, sel);
  if (!box) { console.log("  (no canvas " + sel + ")"); return; }
  const cx = box.x + box.width / 2, cy = box.y + box.height / 2;
  await p.mouse.move(cx, cy, { steps: 14 });
  await p.mouse.down();
  for (let i = 1; i <= 26; i++) {
    await p.mouse.move(cx + (dx * i) / 26, cy + (dy * i) / 26);
    await p.waitForTimeout(38);
  }
  await p.waitForTimeout(500);
  for (let i = 26; i >= 0; i--) {
    await p.mouse.move(cx + (dx * i) / 40, cy + (dy * i) / 40);
    await p.waitForTimeout(24);
  }
  await p.mouse.up();
  await wait(p, 900);
}

const park = (p) => p.mouse.move(1890, 1040, { steps: 6 });

// ---------------------------------------------------------------- the beats
// cap: one or two short lines, burned into the page and written to the .srt.
// Each caption stays on screen for its own reading time (about 13 characters a
// second, plus a beat to settle); `pad` adds deliberate silence on top.
const BEATS = [
  // --- 0. opening -------------------------------------------------------
  { cap: ["Morrow"], pad: 2 },
  { cap: ["A cryptographic governance platform", "for the post-quantum migration."] },
  { cap: ["Recorded against a live build", "and a fictional customer estate."], pad: 1 },

  // --- 1. the problem ---------------------------------------------------
  { cap: ["Traffic your organisation encrypts today", "can be recorded today."], pad: 1 },
  { cap: ["It becomes readable later, once a quantum computer", "can break RSA and elliptic-curve cryptography."], pad: 1.5 },
  { cap: ["So data with a long secrecy requirement", "is already exposed, though nothing has been broken yet."], pad: 1.5 },
  { cap: ["The company here is Example Financial Group —", "an invented bank with thirty-eight endpoints."],
    act: async (p) => { await smoothScroll(p, 260, 2400); } },
  { cap: ["The console opens on posture: inventory, open fixes,", "modelled exposure and crypto-agility."], pad: 1 },
  { cap: ["And the deadlines are not hypothetical.", "CNSA 2.0, NSM-10 and NIST guidance carry published dates."],
    act: async (p) => { await go(p, "qday"); } },
  { cap: ["Optimistic, median and conservative scenarios —", "not one confident date."],
    act: async (p) => { await smoothScroll(p, 320, 2400); } },
  // Scrolls on this view stay above 1200px: the Quantum intelligence feed below
  // that point lists published hardware milestones by the organisation that
  // announced them, and this recording names no real third party.
  { cap: ["Some target dates have already passed.", "Others land in 2030 and 2033."],
    act: async (p) => { await smoothScroll(p, 980, 3000); } },
  { cap: ["The platform models when a relevant quantum computer", "becomes credible — and labels it as a model."],
    act: async (p) => { await smoothScroll(p, 1150, 2400); }, pad: 1.5 },

  // --- 2. discovery -----------------------------------------------------
  { cap: ["Discovery."], act: async (p) => { await go(p, "scans"); }, pad: 1 },
  { cap: ["Everything downstream starts with what you actually run,", "not what the documentation says you run."], pad: 1 },
  { cap: ["Morrow scans TLS endpoints and records", "what each one really negotiated."],
    act: async (p) => { await smoothScroll(p, 430, 2600); } },
  { cap: ["Protocol version, cipher suite, key algorithm,", "key size, and the certificate chain behind it."],
    act: async (p) => { await smoothScroll(p, 980, 2800); } },
  { cap: ["Eight scan runs over five months, so the history", "has shape rather than being one snapshot."],
    act: async (p) => { await smoothScroll(p, 1500, 2800); } },
  { cap: ["The inventory it builds."], act: async (p) => { await go(p, "assets"); } },
  { cap: ["Each endpoint becomes an asset with an owner, a team,", "an environment and a data-confidentiality lifetime."], pad: 1 },
  { cap: ["RSA 2048 and 3072. Elliptic curve P-256 and P-384.", "One gateway already negotiating a hybrid key exchange."],
    act: async (p) => { await smoothScroll(p, 520, 2600); } },
  { cap: ["Confidentiality lifetime is the field that matters most —", "how long this data has to stay secret."],
    act: async (p) => { await smoothScroll(p, 1100, 2800); } },
  { cap: ["Ownership is what turns a cryptographic finding", "into work a named team can be asked to do."], pad: 1.5 },

  // --- 3. exposure ------------------------------------------------------
  { cap: ["Exposure."], act: async (p) => { await go(p, "hndl"); } },
  { cap: ["Harvest now, decrypt later. The question is not", "whether an endpoint is weak today."], pad: 0.5 },
  { cap: ["It is what an adversary could store today", "and read after Q-Day."], pad: 1 },
  { cap: ["So each asset is priced: what the traffic is worth,", "how long it stays secret, the odds it is broken by then."], pad: 1 },
  { cap: ["Exposure grouped by algorithm class.", "RSA-2048 carries most of it."],
    act: async (p) => { await hoverCanvas(p, ".c3d[data-c3d='bar'] canvas", 0.22, 0.55, 2600); } },
  { cap: ["The priority queue is ranked by modelled exposure,", "not by a severity label."],
    act: async (p) => { await park(p); await smoothScroll(p, 420, 2600); } },
  { cap: ["Owner, environment, algorithm, probability broken,", "data category, and how long it has been harvestable."],
    act: async (p) => { await smoothScroll(p, 620, 2400); } },
  // 820 puts both 3D charts in frame and keeps the Adversary landscape row
  // (whose quantum threat model card cites a published milestone by name)
  // below the fold. Do not scroll past it on this view.
  { cap: ["Then the exposure timeline."],
    act: async (p) => { await smoothScroll(p, 820, 2800); } },
  { cap: ["It is a real three-dimensional chart. You can turn it."],
    act: async (p) => { await dragCanvas(p, ".c3d[data-c3d='timeline'] canvas", 190, -55); } },
  { cap: ["Amber is traffic captured but still sealed."],
    act: async (p) => { await hoverCanvas(p, ".c3d[data-c3d='timeline'] canvas", 0.28, 0.6, 2400); } },
  { cap: ["Red is the same traffic, readable,", "once the model's Q-Day wall is crossed."],
    act: async (p) => { await hoverCanvas(p, ".c3d[data-c3d='timeline'] canvas", 0.76, 0.55, 2800); } },
  { cap: ["Beside it, the probability ribbons: one curve per algorithm,", "with the year each reaches a fifty per cent chance."],
    act: async (p) => { await park(p); await hoverCanvas(p, ".c3d[data-c3d='curves'] canvas", 0.55, 0.45, 3000); } },
  { cap: ["Every modelled figure carries a badge saying it is a model,", "with the date, the sources and the assumptions."],
    act: async (p) => { await park(p); }, pad: 1 },
  { cap: ["Nothing here is presented as measurement", "when it is an estimate."], pad: 1.5 },

  // --- 4. evidence ------------------------------------------------------
  { cap: ["Evidence."], act: async (p) => { await go(p, "cbom"); } },
  { cap: ["Exposure is an argument.", "Evidence is what an auditor actually reads."], pad: 1 },
  { cap: ["The cryptographic bill of materials is generated", "from the scans themselves, in CycloneDX 1.6."], pad: 0.5 },
  { cap: ["Every protocol, certificate and algorithm found,", "each with its quantum status."],
    act: async (p) => { await smoothScroll(p, 500, 2600); } },
  { cap: ["Eighty-seven components in this estate.", "Two of them are already post-quantum."],
    act: async (p) => { await smoothScroll(p, 1050, 2800); } },
  { cap: ["Downloadable as JSON or CSV, so it can leave", "the product and still mean something."],
    act: async (p) => { await smoothScroll(p, 0, 2000); } },
  { cap: ["Then the mapping to control frameworks.", "It is honest: this estate scores badly, and it says so."],
    act: async (p) => { await go(p, "governance"); await clickText(p, ".tabs button", "Compliance"); await wait(p, 2600);
                        await smoothScroll(p, 420, 2400); } },
  { cap: ["Evidence packs collect the control artefacts", "with timestamps and a hash chain."],
    act: async (p) => { await smoothScroll(p, 0, 1600); await clickText(p, ".tabs button", "Evidence"); await wait(p, 2600); },
    pad: 2 },
  // Deliberately not clicking "Build evidence pack" here: the pack is a ZIP and
  // the Generated evidence panel prints its bytes, which fills half the screen
  // with mojibake. The frameworks list makes the point without it.

  // --- 5. action --------------------------------------------------------
  { cap: ["Action."], act: async (p) => { await go(p, "remediation"); } },
  { cap: ["Finding cryptography is the easy part.", "Changing it is the work."], pad: 1 },
  { cap: ["Every fix moves through suggested, approved,", "pull request, and verified closed."],
    act: async (p) => { await smoothScroll(p, 420, 2600); } },
  { cap: ["Two are closed and verified against a later scan.", "Seven are still open."], pad: 1 },
  { cap: ["Open one and it carries the file,", "the current configuration, and the proposed change."],
    act: async (p) => { await smoothScroll(p, 560, 2400);
                        await clickText(p, "#view table button", "Open"); await wait(p, 3200); } },
  { cap: ["Approve, reject, validate, open a pull request, mark merged —", "every step is recorded against the asset."],
    act: async (p) => { await wait(p, 2600); } },
  { cap: ["Before you change a certificate authority,", "you want to know what depends on it."],
    act: async (p) => { await p.keyboard.press("Escape").catch(() => {}); await wait(p, 700);
                        await go(p, "graph"); } },
  { cap: ["Blast radius: assets, repositories and fixes", "in one graph you can interrogate."],
    act: async (p) => { await smoothScroll(p, 330, 2400); } },
  { cap: ["Two roots and two issuing authorities sit", "under thirty-eight leaf certificates here."],
    act: async (p) => { await smoothScroll(p, 0, 1600); await clickText(p, ".tabs button", "Certificate blast radius");
                        await wait(p, 3200); await smoothScroll(p, 330, 2200); } },
  { cap: ["If that public root failed, fifty-five dependent nodes", "would be affected, and the model prices it."], pad: 1.5 },
  { cap: ["And a tripwire ladder: five canary keys at five strengths.", "Each only breaks if that algorithm breaks."],
    act: async (p) => { await go(p, "canaries"); await smoothScroll(p, 420, 2600); } },
  { cap: ["So the first one to trip tells you", "how far quantum capability has actually reached."],
    act: async (p) => { await smoothScroll(p, 950, 2600); }, pad: 1.5 },

  // --- 6. governance ----------------------------------------------------
  { cap: ["Governance."], act: async (p) => { await go(p, "board"); } },
  { cap: ["For the board, one composite score —", "with every weight shown."], pad: 0.5 },
  { cap: ["Inventory coverage, open exposure reduction,", "crypto-agility, blocker control."],
    act: async (p) => { await hoverCanvas(p, ".c3d[data-c3d='gauge'] canvas", 0.5, 0.55, 2600); }, pad: 0.5 },
  { cap: ["Components with no evidence behind them are marked", "not measured, rather than scored from nothing."],
    act: async (p) => { await park(p); }, pad: 1 },
  { cap: ["Regulatory exposure is listed by regime,", "with the alignment state the evidence supports."], pad: 1 },
  { cap: ["The executive view is the same view the engineers", "work in. There is no second set of numbers."],
    act: async (p) => { await go(p, "overview"); await smoothScroll(p, 320, 2600); }, pad: 1.5 },

  // --- 7. for the buyer's security team ---------------------------------
  { cap: ["If you are the security team buying this,", "four things matter."],
    act: async (p) => { await go(p, "admin"); } },
  { cap: ["One: tenant isolation is enforced in the database,", "not only in application code."],
    act: async (p) => { await clickText(p, ".tabs button", "Data & isolation"); await wait(p, 2800); } },
  { cap: ["Row-level security, scoped per organisation,", "with a cross-tenant probe you can run yourself."],
    act: async (p) => { await smoothScroll(p, 520, 2600); } },
  { cap: ["Two: vendor support cannot look at your workspace silently.", "Read-only, time-limited, with a stated reason."],
    act: async (p) => { await smoothScroll(p, 0, 1600); await clickText(p, ".tabs button", "Support access"); await wait(p, 2800);
                        await smoothScroll(p, 380, 2200); } },
  { cap: ["Three: the audit trail is hash-chained,", "so a removed entry is detectable."],
    act: async (p) => { await smoothScroll(p, 0, 1600); await clickText(p, ".tabs button", "Audit trail"); await wait(p, 2800); } },
  { cap: ["Four: the operators who run the platform sign in", "through an identity provider, with authenticator MFA."],
    act: async (p) => { await p.goto(BASE + "/enterprise-admin", { waitUntil: "domcontentloaded" }); await wait(p, 3000); } },
  { cap: ["Destructive actions ask for a fresh code.", "The shared key is an emergency credential only."],
    act: async (p) => { await smoothScroll(p, 760, 2800); } },
  { cap: ["And the data boundary is explicit about what", "is allowed to leave your environment."],
    act: async (p) => { await p.goto(BASE + "/data-boundary", { waitUntil: "domcontentloaded" }); await wait(p, 3000);
                        await smoothScroll(p, 720, 2600); } },
  { cap: ["Cryptographic metadata, fingerprints and workflow records", "may cross. Source code, private keys and tokens do not."],
    act: async (p) => { await smoothScroll(p, 1180, 2600); }, pad: 1.5 },

  // --- 8. close ---------------------------------------------------------
  { cap: ["Where to start."],
    act: async (p) => { await p.goto(BASE + "/ui/#overview", { waitUntil: "domcontentloaded" });
                        // A full SPA reload is the slowest thing in the tour: the console refetches
                        // every overview panel. Give it room, or the closing shot opens on skeletons.
                        await p.waitForTimeout(6000); await settled(p, 20000); await wait(p, 4000); } },
  { cap: ["A first pilot is deliberately narrow.", "Six to eight weeks. One organisation."], pad: 1 },
  { cap: ["Three to five critical applications,", "and the assets that support them."], pad: 1 },
  { cap: ["One approved cryptographic inventory.", "One fix carried all the way to verified closure."], pad: 1 },
  { cap: ["One evidence pack an auditor can read."], pad: 1 },
  { cap: ["Start with the endpoints whose data", "has to stay secret the longest."], pad: 1.5 },
  { cap: ["Morrow.", "Cryptographic governance for the post-quantum migration."], pad: 3 },
  { cap: [], pad: 3.5 },
];

// ---------------------------------------------------------------- overlay
const OVERLAY = () => {
  const CSS = `
    #demoCap{position:fixed;left:50%;bottom:52px;transform:translateX(-50%);
      z-index:2147483647;max-width:1500px;box-sizing:border-box;
      background:rgba(7,11,16,.90);border:1px solid rgba(160,190,205,.22);
      border-radius:16px;padding:20px 42px;text-align:center;pointer-events:none;
      box-shadow:0 20px 60px rgba(0,0,0,.55);opacity:0;transition:opacity .3s ease;}
    #demoCap.on{opacity:1}
    #demoCap div{font-family:"Segoe UI",Inter,system-ui,sans-serif;font-size:33px;
      line-height:1.38;font-weight:500;color:#f4f8fb;letter-spacing:.1px;
      text-shadow:0 2px 10px rgba(0,0,0,.85);white-space:nowrap}
    #demoCap div+div{margin-top:4px}
    ::-webkit-scrollbar{width:0;height:0}
  `;
  const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;");
  function ensure() {
    const root = document.documentElement;
    if (!root) return null;
    let el = document.getElementById("demoCap");
    if (el) return el;
    const style = document.createElement("style");
    style.id = "demoCapCss";
    style.textContent = CSS;
    root.appendChild(style);
    el = document.createElement("div");
    el.id = "demoCap";
    root.appendChild(el);
    return el;
  }
  function paint(lines) {
    const el = ensure();
    if (!el) return;
    if (!lines || !lines.length) { el.classList.remove("on"); el.innerHTML = ""; return; }
    el.innerHTML = lines.map((l) => `<div>${esc(l)}</div>`).join("");
    el.classList.add("on");
  }
  window.__cap = (lines) => {
    try { sessionStorage.setItem("__demoCap", JSON.stringify(lines || [])); } catch (e) {}
    paint(lines);
  };
  // A full page load (the marketing pages) re-runs this script: bring the
  // caption that was on screen back with it instead of blinking out.
  const restore = () => {
    let saved = [];
    try { saved = JSON.parse(sessionStorage.getItem("__demoCap") || "[]"); } catch (e) {}
    paint(saved);
  };
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", restore, { once: true });
    restore();
  } else {
    restore();
  }
};

// ---------------------------------------------------------------- srt
const stamp = (s) => {
  const ms = Math.max(0, Math.round(s * 1000));
  const h = String(Math.floor(ms / 3600000)).padStart(2, "0");
  const m = String(Math.floor(ms / 60000) % 60).padStart(2, "0");
  const sec = String(Math.floor(ms / 1000) % 60).padStart(2, "0");
  return `${h}:${m}:${sec},${String(ms % 1000).padStart(3, "0")}`;
};

// ---------------------------------------------------------------- main
(async () => {
  fs.rmSync(RAW, { recursive: true, force: true });
  fs.mkdirSync(RAW, { recursive: true });

  const auth = await (await fetch(`${BASE}/auth/login`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: EMAIL, password: PASSWORD }),
  })).json();

  const browser = await chromium.launch({ channel: "chrome", headless: true, args: ["--force-device-scale-factor=1"] });
  const ctx = await browser.newContext({
    viewport: { width: 1920, height: 1080 },
    deviceScaleFactor: 1,
    recordVideo: { dir: RAW, size: { width: 1920, height: 1080 } },
  });
  await ctx.addInitScript((a) => {
    localStorage.setItem("morrow_token", a.access_token);
    localStorage.setItem("morrow_refresh", a.refresh_token);
    localStorage.setItem("morrow_theme", "dark");
  }, auth);
  await ctx.addInitScript(OVERLAY);

  const page = await ctx.newPage();
  page.setDefaultTimeout(9000);
  const tVideo = Date.now();
  const external = new Set();
  page.on("request", (r) => {
    const u = r.url();
    if (!u.startsWith(BASE) && !u.startsWith("data:") && !u.startsWith("blob:") && !u.startsWith("about:")) external.add(u);
  });
  page.on("pageerror", (e) => console.log("PAGEERR", e.message));

  await page.goto(`${BASE}/ui/#overview`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(9000);          // let the console finish its first load
  await park(page);

  const cues = [];
  for (let i = 0; i < BEATS.length; i++) {
    const b = BEATS[i];
    const t0 = (Date.now() - tVideo) / 1000;
    await caption(page, b.cap);
    if (b.act) await b.act(page);
    // Every caption gets its own reading time (roughly 13 characters a second),
    // measured from when it appeared — whatever the page was doing meanwhile.
    const chars = (b.cap || []).join(" ").length;
    const need = b.cap && b.cap.length ? Math.max(3.2, chars / 13.5 + 1.8) + (b.pad || 0) : (b.pad || 2);
    const spent = (Date.now() - tVideo) / 1000 - t0;
    await wait(page, Math.max(1.0, need - spent) * 1000);
    const t1 = (Date.now() - tVideo) / 1000;
    if (b.cap && b.cap.length) cues.push({ t0, t1, lines: b.cap });
    console.log(`${String(i + 1).padStart(2, "0")}/${BEATS.length}  ${t0.toFixed(1)}s  ${(b.cap[0] || "(clear)").slice(0, 58)}`);
  }

  const total = (Date.now() - tVideo) / 1000;
  await page.close();
  await ctx.close();
  await browser.close();

  const srt = cues.map((c, i) =>
    `${i + 1}\n${stamp(c.t0)} --> ${stamp(Math.min(c.t1 - 0.12, c.t1))}\n${c.lines.join("\n")}\n`).join("\n");
  fs.writeFileSync(path.join(OUT, "morrow-walkthrough.srt"), srt, "utf8");
  fs.writeFileSync(path.join(OUT, "walkthrough-timings.json"),
    JSON.stringify({ total_seconds: total, cues }, null, 2), "utf8");

  const files = fs.readdirSync(RAW).filter((f) => f.endsWith(".webm"));
  console.log("\nrecorded", total.toFixed(1), "s ->", files.join(", "));
  if (external.size) console.log("EXTERNAL REQUESTS:", [...external].join("\n"));
  else console.log("no external requests");
})();
