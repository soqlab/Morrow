/**
 * Renders the Airlock Command product tour.
 *
 *   set NODE_PATH=.tools\video\node_modules
 *   node demo\video\render-tour.js [--work DIR] [--only 12-18]
 *
 * Output: <work>/seg/NNN.mp4   one silent 60 fps segment per shot
 *         <work>/tour.json     the manifest assemble-tour.py reads
 *
 * The clock is Chrome's virtual time, advanced by exactly one frame between
 * screenshots (see render-kit.js). The product's own motion is therefore left
 * switched ON — the constellation field, the ops panels, the view and row
 * entrances, the chart grow-ins, the sweeps on the lead rules — and every one
 * of them is stepped rather than raced, so nothing judders.
 *
 * On top of it sits an overlay layer (tour-overlay.js) that is stepped by
 * frame index: scene cards, kinetic narration, callouts measured from the real
 * elements they point at, count-ups that rewrite the product's own figure as
 * it rises to the value it already held, a cursor, and the transitions.
 */
const fs = require("fs");
const { execFileSync } = require("child_process");
const path = require("path");
const os = require("os");
const K = require("./render-kit");

const FPS = K.FPS;
const argv = process.argv.slice(2);
const argOf = (n, d) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : d; };
const WORK = path.resolve(argOf("--work", path.join(os.tmpdir(), "airlock-tour")));
const ONLY = argOf("--only", null);
// Shots before the range run their setup so the range starts from the page
// state it would really have had. `--setup-from` skips the ones that cannot
// matter: re-rendering shot 61 needs shot 57's navigation to Administration,
// not every navigation since the opening title.
const SETUP_FROM = Number(argOf("--setup-from", 0));
const SEG = path.join(WORK, "seg");

const TRANS_F = 26;            // 0.43 s of transition at the head of a cut


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

/* ======================================================================= tour
 * Each entry is one shot. `cap` is the narration (inline <em> marks the phrase
 * to lift; class "w" is amber, "g" is green). `calls` are callouts anchored to
 * live elements by selector. `counts` rewrite a real figure as it counts up.
 * `verify` asserts on camera that a number the narration claims is really on
 * the screen; the renderer prints a FAIL line if it is not.
 * ==================================================================== */
const SHOTS = [
  /* ---------------------------------------------------------- 0. opening -- */
  {
    sec: "Opening", pre: async (c) => { await c.nav("overview"); },
    card: { kick: "Airlock Command", big: "Cryptographic\ngovernance.", sub: "For the post-quantum migration.", ruleW: 420 },
    secs: 7.2, motion: { kind: "push", amount: 0.03 }, chapter: false, trans: null,
  },
  {
    cap: ["Everything here is a <em>live build</em> reading a seeded database.",
      "The customer is <em>Example Financial Group</em> — an invented bank."],
    pos: "bl", eyebrow: "Overview", secs: 7.0, trans: "fade",
    calls: [{ sel: ".consoleHero", shape: "bracket", label: "LIVE CONSOLE · NOT A MOCK-UP", side: "below", at: [1.4, 6.4] }],
  },

  /* ------------------------------------------------- 1. the problem ------- */
  {
    sec: "1. The problem", trans: "iris",
    card: { kick: "One", big: "Harvest now.\nDecrypt later.", sub: "", ruleW: 300, scrim: 0.97 },
    secs: 6.6,
  },
  {
    cap: ["Traffic your organisation encrypts <em>today</em>", "can be recorded <em>today</em>."],
    pos: "c", secs: 5.6, trans: "fade", motion: { kind: "push", amount: 0.022 },
  },
  {
    cap: ["It becomes readable <em class='w'>later</em>, once a quantum computer",
      "can break RSA and elliptic-curve cryptography."],
    pos: "c", secs: 6.4, trans: null,
  },
  {
    cap: ["So data with a <em>long secrecy requirement</em> is already exposed —",
      "though nothing has been broken yet."],
    pos: "bl", secs: 6.6, trans: "wipeleft",
    pre: async (c) => { await c.scroll(0); },
    motion: { kind: "scroll", to: 300, secs: 3.4 },
  },
  {
    cap: ["The console opens on <em>posture</em>: inventory, open fixes,", "modelled exposure and crypto-agility."],
    pos: "bl", secs: 7.2, trans: null,
    motion: { kind: "scroll", to: 690, secs: 4.2 },
    calls: [{ sel: ".opsPanel", shape: "bracket", label: "SCAN ACTIVITY · RUNNING NOW", side: "above", at: [2.6, 6.8] }],
  },
  {
    sec: "1. The problem", pre: async (c) => { await c.nav("qday"); },
    cap: ["And the deadlines are not hypothetical.", "<em>CNSA 2.0</em>, <em>NSM-10</em> and NIST guidance carry published dates."],
    pos: "bl", eyebrow: "Q-Day Forecast", secs: 7.4, trans: "push",
    // No count-up here: these figures are years, and a year rising from
    // nothing reads as a broken number rather than as an arrival.
    verify: [{ sel: ".kpi.lift", nth: 1, has: "Median" }],
  },
  {
    cap: ["<em>Optimistic</em>, <em>median</em> and <em>conservative</em> scenarios —", "not one confident date."],
    pos: "bl", secs: 6.4, trans: null,
    calls: [{ sel: ".kpi.lift", nth: 1, shape: "box", label: "MEDIAN SCENARIO", side: "below", at: [0.8, 5.6] }],
    motion: { kind: "scroll", to: 360, secs: 3.2, lead: 1.4 },
  },
  {
    // Scrolls on this view stop at 1150: below it the quantum intelligence feed
    // names the organisations that published each hardware result, and this
    // recording names no real third party.
    cap: ["Some target dates have already <em>passed</em>.", "Others land in <em class='w'>2030</em> and <em class='w'>2033</em>."],
    pos: "bl", secs: 7.6, trans: null,
    motion: { kind: "scroll", to: 980, secs: 4.6 },
    calls: [{ sel: ".card.lift", text: "Migration milestones", shape: "bracket", label: "PUBLISHED SOURCES, EACH CITED", side: "left", at: [3.0, 7.2] }],
  },
  {
    cap: ["The platform models when a relevant quantum computer becomes credible —",
      "and <em>labels it as a model</em>."],
    pos: "bl", secs: 6.6, trans: null, motion: { kind: "scroll", to: 1150, secs: 2.6 },
  },

  /* --------------------------------------------------- 2. discovery ------- */
  {
    sec: "2. Discovery", pre: async (c) => { await c.nav("scans"); },
    card: { kick: "Two", big: "Discovery.", sub: "What you actually run, not what the documentation says you run.", ruleW: 300 },
    secs: 6.4, trans: "bars", motion: { kind: "push", amount: 0.026 },
  },
  {
    cap: ["Airlock Command scans TLS endpoints and records", "what each one <em>really negotiated</em>."],
    pos: "bl", eyebrow: "TLS Scanner", secs: 6.6, trans: "fade",
    calls: [{ sel: ".card.lift", text: "New scan", shape: "box", label: "EXTERNAL POSTURE CHECK", side: "right", at: [1.2, 6.0] }],
  },
  {
    cap: ["Protocol version, cipher suite, key algorithm,", "key size, and the certificate chain behind it."],
    pos: "bl", secs: 7.0, trans: null, motion: { kind: "scroll", to: 460, secs: 3.8 },
  },
  {
    cap: ["<em>Eight scan runs</em> over five months, so the history",
      "has shape rather than being one snapshot."],
    pos: "tl", secs: 7.4, trans: null, motion: { kind: "scroll", to: 907, secs: 4.0 },
    calls: [{ sel: ".card.lift", text: "Recent scans", shape: "bracket", label: "8 RUNS · APRIL TO SEPTEMBER", side: "left", at: [3.2, 7.0] }],
    verify: [{ sel: ".card.lift", text: "Recent scans", has: "8 most recent" }],
  },
  {
    sec: "2. Discovery", pre: async (c) => { await c.nav("assets"); },
    cap: ["The inventory it builds.", "<em>Thirty-eight endpoints</em>, every one with an owner beside it."],
    pos: "bl", eyebrow: "Asset Inventory", secs: 7.2, trans: "wiperight",
    counts: [{ sel: ".kpi.lift", nth: 0, at: [0.6, 2.4] }, { sel: ".kpi.lift", nth: 3, at: [0.9, 2.7] }],
    calls: [{ sel: ".kpi.lift", nth: 0, shape: "box", label: "TOTAL ASSETS", side: "below", at: [2.4, 6.8] }],
    verify: [{ sel: ".kpi.lift", nth: 0, has: "38" }],
  },
  {
    cap: ["Each endpoint carries an <em>owner</em>, a <em>team</em>, an <em>environment</em>",
      "and a data-confidentiality lifetime."],
    pos: "bl", secs: 7.0, trans: null, motion: { kind: "scroll", to: 300, secs: 3.0 },
  },
  {
    cap: ["RSA 2048 and 3072. Elliptic curve P-256 and P-384.",
      "One gateway already negotiating a <em class='g'>hybrid key exchange</em>."],
    pos: "bl", secs: 7.6, trans: null, motion: { kind: "scroll", to: 560, secs: 3.4 },
  },
  {
    cap: ["Confidentiality lifetime is the field that matters most —",
      "<em>how long this data has to stay secret</em>."],
    pos: "tl", secs: 7.6, trans: null, motion: { kind: "scroll", to: 1100, secs: 4.4 },
  },
  {
    cap: ["Ownership is what turns a cryptographic finding", "into work a <em>named team</em> can be asked to do."],
    pos: "tl", secs: 7.4, trans: null, motion: { kind: "scroll", to: 1560, secs: 4.2 },
    calls: [{ sel: ".card.lift", text: "Top owners", shape: "bracket", label: "11 DISTINCT OWNERS", side: "left", at: [3.4, 7.0] }],
  },

  /* ---------------------------------------------------- 3. exposure ------- */
  {
    sec: "3. Exposure", pre: async (c) => { await c.nav("hndl"); },
    card: { kick: "Three", big: "Exposure.", sub: "Not whether an endpoint is weak today.", ruleW: 300 },
    secs: 6.2, trans: "iris", motion: { kind: "push", amount: 0.026 },
  },
  {
    cap: ["It is what an adversary could <em>store today</em>", "and read <em class='w'>after Q-Day</em>."],
    pos: "c", secs: 6.0, trans: "fade",
    calls: [{ sel: ".vendSummary", shape: "bracket", label: "RISK TIERS · 38 ASSETS", side: "below", at: [1.6, 5.6] }],
  },
  {
    cap: ["So each asset is <em>priced</em>: what the traffic is worth,",
      "how long it stays secret, the odds it is broken by then."],
    pos: "bl", secs: 7.4, trans: null, motion: { kind: "scroll", to: 240, secs: 2.8 },
  },
  {
    sec: "3. Exposure",
    pre: async (c) => { await c.scroll(240); await c.hover(".c3d[data-c3d='bar'] canvas", 0.22, 0.55); },
    cap: ["Exposure grouped by <em>algorithm class</em>.", "<em class='w'>RSA-2048</em> carries most of it."],
    pos: "tl", secs: 6.4, trans: "wipeup",
    calls: [{ sel: ".c3d[data-c3d='bar']", shape: "bracket", label: "HOVERED · REAL VALUE", side: "left", at: [1.4, 6.0] }],
  },
  {
    pre: async (c) => { await c.park(); },
    cap: ["The priority queue is ranked by <em>modelled exposure</em>,", "not by a severity label."],
    pos: "tl", secs: 7.0, trans: "fade", motion: { kind: "scroll", to: 470, secs: 3.0, lead: 1.4 },
  },
  {
    cap: ["Owner, environment, algorithm, <em>probability broken</em>,",
      "data category, and how long it has been harvestable."],
    pos: "tl", secs: 7.0, trans: null, motion: { kind: "scroll", to: 640, secs: 2.8 },
  },
  {
    // 820 keeps the adversary-landscape row, which cites a published milestone
    // by name, below the fold. Do not scroll past it on this view.
    cap: ["Then the <em>exposure timeline</em>."],
    pos: "tl", secs: 5.2, trans: null, motion: { kind: "scroll", to: 820, secs: 3.0 },
  },
  {
    cap: ["It is a real three-dimensional chart.", "You can <em>turn it</em>."],
    pos: "tl", secs: 6.2, trans: null,
    motion: { kind: "rotate", key: "timeline", from: -0.18, to: 0.46, secs: 3.4, hold: 0.4, back: true },
    cursor: { path: [[1500, 700], [1180, 640], [1420, 660]], at: [0.6, 5.4] },
  },
  {
    pre: async (c) => { await c.hover(".c3d[data-c3d='timeline'] canvas", 0.30, 0.62); },
    cap: ["<em class='w'>Amber</em> is traffic captured but still sealed."],
    pos: "tl", secs: 5.0, trans: "fade",
  },
  {
    pre: async (c) => { await c.hover(".c3d[data-c3d='timeline'] canvas", 0.78, 0.55); },
    cap: ["<em>Red</em> is the same traffic, readable,", "once the model's <em class='w'>Q-Day wall</em> is crossed."],
    pos: "tl", secs: 6.4, trans: "fade",
  },
  {
    pre: async (c) => { await c.hover(".c3d[data-c3d='curves'] canvas", 0.55, 0.45); },
    cap: ["Beside it, the probability ribbons: one curve per algorithm,",
      "with the year each reaches a <em>fifty per cent chance</em>."],
    pos: "tl", secs: 7.2, trans: "fade",
  },
  {
    pre: async (c) => { await c.park(); },
    cap: ["Every modelled figure carries a badge saying it <em>is</em> a model,",
      "with the date, the sources and the assumptions."],
    pos: "bl", secs: 7.4, trans: "wipedown", motion: { kind: "scroll", to: 470, secs: 3.0, lead: 1.6 },
  },
  {
    cap: ["Nothing here is presented as measurement", "when it is an <em>estimate</em>."],
    pos: "bl", secs: 5.6, trans: null,
  },

  /* ---------------------------------------------------- 4. evidence ------- */
  {
    sec: "4. Evidence", pre: async (c) => { await c.nav("cbom"); },
    card: { kick: "Four", big: "Evidence.", sub: "Exposure is an argument. Evidence is what an auditor reads.", ruleW: 300 },
    secs: 6.6, trans: "bars", motion: { kind: "push", amount: 0.026 },
  },
  {
    cap: ["The cryptographic bill of materials is generated",
      "from the scans themselves, in <em>CycloneDX 1.6</em>."],
    pos: "bl", eyebrow: "CBOM · SBOM", secs: 7.0, trans: "fade",
    counts: [{ sel: ".vendSummary", at: [0.6, 2.6] }],
    calls: [{ sel: ".vendSummary", shape: "bracket", label: "87 COMPONENTS · 2 POST-QUANTUM", side: "below", at: [2.4, 6.6] }],
    verify: [{ sel: ".vendSummary", has: "87 components" }],
  },
  {
    cap: ["Every protocol, certificate and algorithm found,", "each with its <em>quantum status</em>."],
    pos: "tl", secs: 6.6, trans: null, motion: { kind: "scroll", to: 290, secs: 3.0 },
  },
  {
    cap: ["Eighty-seven components in this estate.", "<em class='g'>Two</em> of them are already post-quantum."],
    pos: "tl", secs: 6.6, trans: null, motion: { kind: "scroll", to: 407, secs: 2.6 },
  },
  {
    cap: ["Downloadable as <em>JSON</em> or <em>CSV</em>, so it can leave", "the product and still mean something."],
    pos: "bl", secs: 6.8, trans: null, motion: { kind: "scroll", to: 0, secs: 4.0 },
  },
  {
    sec: "4. Evidence", pre: async (c) => { await c.nav("governance"); await c.tab("Compliance"); },
    cap: ["Then the mapping to <em>control frameworks</em>.",
      "It is honest: this estate scores badly, and it says so."],
    pos: "bl", eyebrow: "Governance · Compliance", secs: 7.4, trans: "push",
  },
  {
    // The evidence pack is deliberately not built on camera: it is a ZIP, and
    // the Generated evidence panel prints its bytes.
    pre: async (c) => { await c.scroll(0); await c.tab("Evidence"); },
    cap: ["Evidence packs collect the control artefacts", "with timestamps and a <em>hash chain</em>."],
    pos: "bl", eyebrow: "Governance · Evidence", secs: 7.0, trans: "wipeleft",
    motion: { kind: "scroll", to: 170, secs: 4.4, lead: 1.0 },
  },

  /* ------------------------------------------------------ 5. action ------- */
  {
    sec: "5. Action", pre: async (c) => { await c.nav("remediation"); },
    card: { kick: "Five", big: "Action.", sub: "Finding cryptography is the easy part. Changing it is the work.", ruleW: 300 },
    secs: 6.6, trans: "iris", motion: { kind: "push", amount: 0.026 },
  },
  {
    cap: ["Every fix moves through <em>suggested</em>, <em>approved</em>,",
      "<em>pull request</em>, and <em class='g'>verified closed</em>."],
    pos: "bl", eyebrow: "Remediation", secs: 7.4, trans: "fade",
    counts: [{ sel: ".kpi.lift", nth: 0, at: [0.6, 2.4] }],
    calls: [{ sel: ".card.lift", text: "Pipeline", shape: "bracket", label: "PIPELINE", side: "right", at: [2.2, 7.0] }],
  },
  {
    cap: ["<em class='g'>Two</em> are closed and verified against a later scan.", "<em class='w'>Seven</em> are still open."],
    pos: "bl", secs: 6.6, trans: null, motion: { kind: "scroll", to: 560, secs: 3.2 },
    verify: [{ sel: ".kpi.lift", nth: 0, has: "7" }],
  },
  {
    pre: async (c) => { await c.scroll(560); },
    cap: ["Open one and it carries the file,", "the current configuration, and the <em>proposed change</em>."],
    pos: "bl", secs: 8.0, trans: "fade",
    cursor: { path: [[1300, 860], [1660, 726]], at: [0.4, 3.4], clickAt: 2.2, clickSel: "#view table button", clickText: "Open" },
  },
  {
    cap: ["Approve, reject, validate, open a pull request, mark merged —",
      "every step is <em>recorded against the asset</em>."],
    pos: "bl", secs: 7.2, trans: null, motion: { kind: "scroll", to: 320, secs: 3.0 },
  },
  {
    sec: "5. Action",
    pre: async (c) => { await c.esc(); await c.nav("graph"); },
    cap: ["Before you change a certificate authority,", "you want to know <em>what depends on it</em>."],
    pos: "bl", eyebrow: "Blast Radius", secs: 7.0, trans: "push",
    counts: [{ sel: ".kpi.lift", nth: 0, at: [0.5, 2.3] }, { sel: ".kpi.lift", nth: 3, at: [0.8, 2.6] }],
  },
  {
    cap: ["Assets, repositories and fixes", "in <em>one graph you can interrogate</em>."],
    pos: "bl", secs: 6.6, trans: null, motion: { kind: "scroll", to: 330, secs: 3.0 },
  },
  {
    pre: async (c) => { await c.scroll(0); await c.tab("Certificate blast radius"); },
    cap: ["<em>Two roots</em> and two issuing authorities sit", "under <em>thirty-eight leaf certificates</em> here."],
    pos: "bl", secs: 7.2, trans: "wiperight", motion: { kind: "scroll", to: 330, secs: 3.0, lead: 1.8 },
  },
  {
    cap: ["If that public root failed, the dependent nodes beneath it", "would be affected — and the model <em>prices it</em>."],
    pos: "bl", secs: 7.2, trans: null, motion: { kind: "scroll", to: 560, secs: 3.0 },
  },
  {
    sec: "5. Action", pre: async (c) => { await c.nav("canaries"); },
    cap: ["And a tripwire ladder: <em>five canary keys</em> at five strengths.",
      "Each only breaks if <em>that</em> algorithm breaks."],
    pos: "bl", eyebrow: "Canaries & QTISN", secs: 7.6, trans: "wipeup",
    calls: [{ sel: ".sec", text: "Tripwire ladder", shape: "bracket", label: "ALPHA → OMEGA · NONE TRIPPED", side: "below", at: [2.2, 7.2] }],
    motion: { kind: "scroll", to: 300, secs: 3.0, lead: 1.6 },
  },
  {
    cap: ["So the first one to trip tells you", "<em>how far quantum capability has actually reached</em>."],
    pos: "bl", secs: 6.6, trans: null,
  },

  /* -------------------------------------------------- 6. governance ------- */
  {
    sec: "6. Governance", pre: async (c) => { await c.nav("board"); },
    card: { kick: "Six", big: "Governance.", sub: "One composite score — with every weight shown.", ruleW: 300 },
    secs: 6.4, trans: "bars", motion: { kind: "push", amount: 0.026 },
  },
  {
    cap: ["For the board, one number — <em>with its working</em>."],
    pos: "bl", eyebrow: "Board & ROI", secs: 6.2, trans: "fade",
    counts: [{ sel: ".kpi.lift", nth: 0, at: [0.5, 2.6] }],
    calls: [{ sel: ".kpi.lift", nth: 0, shape: "box", label: "BOARD RISK SCORE", side: "below", at: [2.4, 5.8] }],
    verify: [{ sel: ".kpi.lift", nth: 0, has: "/100" }],
  },
  {
    cap: ["Inventory coverage, open exposure reduction,", "crypto-agility, blocker control."],
    pos: "tl", secs: 6.4, trans: null,
    motion: { kind: "rotate", key: "gauge", from: -0.26, to: 0.30, secs: 3.0, hold: 0.4, back: true },
  },
  {
    pre: async (c) => { await c.park(); },
    cap: ["Components with no evidence behind them are marked", "<em>not measured</em>, rather than scored from nothing."],
    pos: "bl", secs: 7.2, trans: "fade",
    calls: [{ sel: ".card.lift", text: "Score composition", shape: "bracket", label: "EVERY WEIGHT, SHOWN", side: "right", at: [1.8, 6.8] }],
  },
  {
    cap: ["Regulatory exposure is listed by regime,", "with the alignment state <em>the evidence supports</em>."],
    pos: "bl", secs: 6.8, trans: null,
  },
  {
    sec: "6. Governance", pre: async (c) => { await c.nav("overview"); },
    cap: ["The executive view is the same view the engineers work in.", "There is <em>no second set of numbers</em>."],
    pos: "bl", secs: 7.4, trans: "push", motion: { kind: "scroll", to: 340, secs: 3.2, lead: 1.6 },
  },

  /* ---------------------------------------------- 7. the security team ---- */
  {
    sec: "7. For the security team", pre: async (c) => { await c.nav("admin"); },
    card: { kick: "Seven", big: "Four questions\nfrom your\nsecurity team.", sub: "", ruleW: 300 },
    secs: 6.8, trans: "iris",
  },
  {
    pre: async (c) => { await c.tab("Data & isolation"); },
    cap: ["<em>One:</em> tenant isolation is enforced in the database,", "not only in application code."],
    pos: "bl", eyebrow: "Administration · Data & isolation", secs: 7.2, trans: "fade",
  },
  {
    cap: ["Row-level security, scoped per organisation,", "with a <em>cross-tenant probe you can run yourself</em>."],
    pos: "bl", secs: 6.8, trans: null,
  },
  {
    pre: async (c) => { await c.scroll(0); await c.tab("Support access"); },
    cap: ["<em>Two:</em> vendor support cannot look at your workspace silently.",
      "Read-only, time-limited, with a stated reason."],
    pos: "bl", eyebrow: "Administration · Support access", secs: 7.6, trans: "wipeleft",
  },
  {
    pre: async (c) => { await c.nav("admin"); await c.tab("Audit trail"); },
    cap: ["<em>Three:</em> the audit trail is <em>hash-chained</em>,", "so a removed entry is detectable."],
    pos: "bl", eyebrow: "Administration · Audit trail", secs: 7.2, trans: "wipeleft",
    motion: { kind: "scroll", to: 300, secs: 2.8, lead: 2.0 },
  },
  {
    // The operator workspace carries its own WebGL field, and on this page it
    // accumulates until Chrome stops answering a screenshot about six seconds
    // in. It is stopped here through the product's own control — the same one
    // the pause button in the console uses — so the shot can be filmed. The
    // scroll supplies the motion.
    sec: "7. For the security team",
    pre: async (c) => {
      await c.load("/enterprise-admin");
      await c.page.evaluate(() => { try { window.airlockFabric.setRunning(false); } catch (e) { /* none */ } });
    },
    cap: ["<em>Four:</em> the operators who run the platform sign in",
      "through an identity provider, with authenticator MFA."],
    // Render this one with PQC_NO_GPU=1: on the GPU path Chrome stops
    // answering a screenshot a few seconds into this page.
    pos: "bl", eyebrow: "Operator workspace", secs: 7.4, trans: "push",
    motion: { kind: "scroll", to: 150, secs: 4.6, lead: 1.2 },
  },
  {
    cap: ["Destructive actions ask for a <em>fresh code</em>.", "The shared key is an emergency credential only."],
    pos: "bl", secs: 7.0, trans: null, motion: { kind: "scroll", to: 760, secs: 3.6 },
  },
  {
    pre: async (c) => { await c.load("/data-boundary"); },
    cap: ["And the <em>data boundary</em> is explicit about what", "is allowed to leave your environment."],
    pos: "bl", eyebrow: "Data boundary", secs: 7.2, trans: "wiperight",
    motion: { kind: "scroll", to: 720, secs: 3.6, lead: 1.8 },
  },
  {
    cap: ["Cryptographic metadata, fingerprints and workflow records <em>may</em> cross.",
      "Source code, private keys and tokens <em class='w'>do not</em>."],
    pos: "bl", secs: 7.8, trans: null, motion: { kind: "scroll", to: 1180, secs: 3.6 },
  },

  /* ------------------------------------------------------- 8. close ------- */
  {
    sec: "8. Close", pre: async (c) => { await c.load("/ui/#overview"); },
    card: { kick: "Eight", big: "Where to start.", sub: "A first pilot is deliberately narrow.", ruleW: 300 },
    secs: 6.6, trans: "bars", motion: { kind: "push", amount: 0.026 },
  },
  {
    cap: ["<em>Six to eight weeks.</em> One organisation.", "Three to five critical applications."],
    pos: "bl", secs: 6.8, trans: "fade", motion: { kind: "scroll", to: 300, secs: 3.0 },
  },
  {
    cap: ["One approved cryptographic inventory.", "One fix carried all the way to <em class='g'>verified closure</em>."],
    pos: "bl", secs: 7.0, trans: null, motion: { kind: "scroll", to: 640, secs: 3.4 },
  },
  {
    cap: ["One <em>evidence pack</em> an auditor can read."],
    pos: "bl", secs: 5.2, trans: null,
  },
  {
    pre: async (c) => { await c.nav("overview"); },
    cap: ["Start with the endpoints whose data", "has to stay secret the <em>longest</em>."],
    pos: "bl", secs: 6.6, trans: "wipedown",
  },
  {
    card: { kick: "Airlock Command", big: "Cryptographic\ngovernance.", sub: "For the post-quantum migration.", ruleW: 420, scrim: 0.97, hold: true },
    secs: 8.5, trans: "iris", chapter: false, motion: { kind: "push", amount: 0.024 },
  },
];

/* ==================================================================== timing */
function plannedSeconds(s) {
  let need = s.secs || 0;
  const chars = (s.cap || []).map(K.stripTags).join(" ").length;
  if (chars) need = Math.max(need, chars / 15.5 + 2.0, 4.0);
  if (s.card) need = Math.max(need, 5.8);
  const m = s.motion;
  if (m && m.kind === "scroll") need = Math.max(need, m.secs + (m.lead || 0.8) + 1.1);
  if (m && m.kind === "rotate") need = Math.max(need, m.secs + 1.4);
  return need;
}

/* ================================================================== renderer */
(async () => {
  fs.mkdirSync(SEG, { recursive: true });
  let lo = 0, hi = SHOTS.length - 1;
  if (ONLY) { const m = /^(\d+)(?:-(\d+))?$/.exec(ONLY); lo = Number(m[1]); hi = m[2] ? Number(m[2]) : lo; }

  const frames = SHOTS.map((s) => Math.round(plannedSeconds(s) * FPS));
  const total = frames.reduce((a, b) => a + b, 0);
  console.log(`${SHOTS.length} shots, ${(total / FPS).toFixed(1)}s planned (${total} frames)`);

  const { browser, page, cdp, external } = await K.open();
  const clock = K.makeClock(cdp);

  /* ---- page control, all of it on the virtual clock ---- */
  const c = {
    page, clock,
    scroll: (y) => K.scrollTo(page, y),
    park: async () => { await page.mouse.move(1905, 1058, { steps: 3 }); await clock.run(120); },
    esc: async () => { await page.keyboard.press("Escape").catch(() => {}); await clock.run(500); },
    async settle() { await K.settled(page, clock); },
    async nav(route) {
      await K.insist("nav " + route, () => page.evaluate((r) => {
        const first = document.querySelector("#view") && document.querySelector("#view").firstElementChild;
        if (first) first.setAttribute("data-demo-outgoing", "1");
        const b = document.querySelector(`#nav button.nav[data-go="${r}"]`);
        if (b) b.click(); else location.hash = "#" + r;
      }, route), 12000).catch(() => {});
      await clock.run(400);
      await K.settled(page, clock);
      await K.scrollTo(page, 0);
      await clock.run(600);
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
      return ok;
    },
    async load(url) {
      // A full page load needs a running clock, but an unbounded one lets the
      // page's animation loops run flat out and stops the renderer answering
      // anything. So the clock is fed in small bounded chunks, roughly three
      // times real time, only until the document arrives.
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
      await clock.run(600);
      await page.evaluate(() => window.__ov && window.__ov.mount());
      // `settled()` watches for the console's `#view` to stop growing. The
      // public pages have no `#view`, so it would spin for its whole cap —
      // thirty virtual seconds of a page whose scene is drawing flat out,
      // which is what left Chrome unable to answer a screenshot afterwards.
      const isConsole = await K.insist("has #view", () => page.evaluate(
        () => !!document.querySelector("#view")), 8000).catch(() => false);
      await K.settled(page, clock, isConsole ? 30000 : 4000);
      await K.scrollTo(page, 0);
      await clock.run(600);
    },
    async hover(sel, fx, fy) {
      const b = await page.locator(sel).first().boundingBox().catch(() => null);
      if (!b) { console.log("    (no " + sel + ")"); return null; }
      const x = b.x + b.width * fx, y = b.y + b.height * fy;
      await page.mouse.move(x - 40, y - 30, { steps: 4 });
      await page.mouse.move(x, y, { steps: 8 });
      await clock.run(400);
      return [x, y];
    },
  };

  /* ---- pose hook for the 3D charts: the product's own renderer, our angle -- */
  const installPose = () => K.insist("installPose", () => page.evaluate(() => {
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
  }), 12000).catch(() => false);

  // The first load happens in real time; the clock is taken over once the
  // document is there and never given back except across a full page load.
  await page.goto(`${K.BASE}/ui/#overview`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1500);
  await clock.take();
  await K.settled(page, clock, 40000);
  await c.park();

  const manifest = [];
  let elapsedF = 0;
  let prevShot = null;              // the still the next transition wipes away
  let chapter = { label: "Opening", n: "00" };

  for (let i = 0; i < SHOTS.length; i++) {
    const s = SHOTS[i];
    const n = frames[i];
    if (s.sec) chapter = { label: s.sec, n: String(i).padStart(2, "0") };
    manifest.push({ i, frames: n, seconds: n / FPS, cap: (s.cap || []).map(K.stripTags), start: elapsedF / FPS });
    const startF = elapsedF;
    elapsedF += n;

    if (i < lo || i > hi) {
      // Shots before the range still run their setup, so the range starts from
      // the page state it would really have had. Shots after it are skipped
      // outright.
      if (i < lo && i >= SETUP_FROM) {
        if (s.pre) await s.pre(c);
        if (s.motion && s.motion.kind === "scroll") await c.scroll(s.motion.to);
      }
      prevShot = null;
      continue;
    }

    const t0 = Date.now();
    if (s.pre) {
      try {
        await s.pre(c);
      } catch (e) {
        console.log("    (setup failed: " + String(e.message).slice(0, 80) + "; reloading)");
        await c.load("/ui/#overview");
        for (let j = Math.max(0, i - 8); j <= i; j++) {
          const q = SHOTS[j];
          if (q.pre) await q.pre(c);
          if (j < i && q.motion && q.motion.kind === "scroll") await c.scroll(q.motion.to);
        }
      }
    }
    await installPose();
    // Replay the console's own staggered entrance so it is filmed rather than
    // missed while the data was loading.
    if (s.pre || s.card) { await K.replayEntrance(page); }

    /* ---- on-camera fact check ---- */
    for (const v of (s.verify || [])) {
      const got = await K.insist("verify", () => page.evaluate((q) => {
        let e = null;
        if (q.text) { for (const x of document.querySelectorAll(q.sel)) if ((x.textContent || "").includes(q.text)) { e = x; break; } }
        else e = document.querySelectorAll(q.sel)[q.nth || 0];
        return e ? (e.textContent || "").replace(/\s+/g, " ").trim().slice(0, 120) : null;
      }, v), 12000).catch(() => null);
      if (!got || !got.includes(v.has)) console.log(`  VERIFY FAIL shot ${i}: "${v.has}" not in ${JSON.stringify(got)}`);
    }

    /* ---- the overlay plan, in frames ---- */
    const F = (sec) => Math.round(sec * FPS);
    const items = [];
    if (!prevShot && s.trans && i > 0) {
      prevShot = lastFrameOf(path.join(SEG, String(i - 1).padStart(3, "0") + ".mp4"));
    }
    const transF = (s.trans && prevShot) ? TRANS_F : 0;
    if (transF) items.push({ k: "trans", a: 0, b: transF, kind: s.trans });
    if (s.card) {
      items.push({ k: "card", a: transF, b: n - F(0.2), kick: s.card.kick, big: s.card.big,
        sub: s.card.sub, ruleW: s.card.ruleW, scrim: s.card.scrim,
        inF: 30, outF: s.card.hold ? 2 : 34 });
    }
    if (s.cap && s.cap.length) {
      const a = transF + F(0.25);
      items.push({ k: "narr", a, b: n - F(0.35), pos: s.pos || "bl", eyebrow: s.eyebrow,
        lines: s.cap, w: s.w || 1430, stagger: 8, outF: 18 });
    }
    if (s.chapter !== false) {
      items.push({ k: "chap", a: transF + F(0.4), b: n - F(0.3), n: chapter.n, label: chapter.label });
    }
    for (const call of (s.calls || [])) {
      const r = await K.insist("callout rect", () => page.evaluate(
        (q) => window.__ov.rect(q.sel, { text: q.text, nth: q.nth }), call), 12000).catch(() => null);
      if (!r) { console.log(`    (no callout target ${call.sel}${call.text ? " :" + call.text : ""})`); continue; }
      items.push({ k: "call", a: F(call.at[0]), b: Math.min(n, F(call.at[1])), sel: call.sel,
        text: call.text, nth: call.nth, shape: call.shape || "box", label: call.label,
        side: call.side, tone: call.tone, rect: r, pad: call.pad });
    }
    const counts = [];
    for (const cu of (s.counts || [])) {
      counts.push({ k: "count", a: F(cu.at[0]), b: F(cu.at[1]), sel: cu.sel, nth: cu.nth });
    }
    items.push(...counts);
    let clickFrame = null, clickDo = null;
    if (s.cursor) {
      const cur = s.cursor;
      items.push({ k: "cursor", a: F(cur.at[0]), b: Math.min(n, F(cur.at[1])), path: cur.path,
        click: cur.clickAt != null ? F(cur.clickAt) : null });
      if (cur.clickAt != null && cur.clickSel) {
        clickFrame = F(cur.clickAt);
        clickDo = async () => {
          const ok = await K.insist("click", () => page.evaluate((q) => {
            const all = [...document.querySelectorAll(q.sel)];
            const e = q.text ? all.find((x) => (x.textContent || "").trim().includes(q.text)) : all[0];
            if (!e) return false;
            e.click();
            return true;
          }, { sel: cur.clickSel, text: cur.clickText }), 12000).catch(() => false);
          if (!ok) console.log("    (nothing to click: " + cur.clickSel + ")");
        };
      }
    }
    const prog = [startF / (total || 1), (startF + n) / (total || 1)];
    await K.insist("overlay begin", () => page.evaluate((p) => window.__ov.begin(p), { dur: n, prog, items }), 15000);

    /* ---- the camera track for this shot ---- */
    const zoomOf = [];
    const scrollOf = [];
    const yawOf = [];
    // A shot with nothing of its own to do still gets a slow push. That is
    // partly taste — a ten-second hold is the thing the first cut was rejected
    // for — and partly arithmetic: the product's ambient field redraws at the
    // twenty frames a second it asks for, so a held frame is identical to the
    // one before it two times in three. The push is rendered by re-rasterising
    // the page at a fractional scale, so every frame differs.
    // `still: true` opts a shot out of that default. One shot needs it: the
    // operator workspace stops answering a screenshot once anything is
    // re-rasterising the whole frame, and a held frame is the only way it can
    // be filmed at all. It is the only shot in the film whose ambient motion
    // is the product's own twenty frames a second and nothing else.
    const m = s.still ? null : (s.motion || { kind: "push", amount: 0.017 });

    /* --------------------------------------------------------------- drift
     * Every frame of every shot has to differ from the one before it, and
     * neither the product nor a push can promise that. The product's ambient
     * field asks for twenty frames a second, so two frames in three are
     * identical wherever it is the only thing moving; and a push slow enough
     * to be tasteful moves the frame edge by about a fortieth of a pixel,
     * which rounds away.
     *
     * So the camera itself drifts: the clip rectangle is nudged by a quarter
     * of a CSS pixel a frame, on a slow diagonal that never repeats a
     * position within a shot. That is the same magnitude as the slowest
     * scroll in the film, which measurably advances on every frame, and it
     * works on a view with nothing to scroll. The frame is captured 6 px
     * inside the viewport so the drift has somewhere to go.
     */
    // A circle, not a Lissajous: a sine has a turning point, and at a turning
    // point the camera is stationary and the frame repeats. A circle traversed
    // at a constant rate never is. Radius 8 px is 0.4 % of the frame and the
    // cycle takes 3.4 s, so it reads as a held frame; the speed is a quarter of
    // a CSS pixel a frame, the same as the slowest scroll in the film, which
    // measurably advances on every frame.
    const DRIFT_PX = 0.5;               // CSS px a frame = 1 device px at 2x
    const DRIFT_R = 16;                 // CSS px radius, inside the 19 px margin
    const drift = (f) => {
      const a = (f * DRIFT_PX) / DRIFT_R;
      return [Math.cos(a) * DRIFT_R, Math.sin(a) * DRIFT_R];
    };
    if (m && m.kind === "push") {
      for (let f = 0; f < n; f++) zoomOf.push(1 + m.amount * (f / (n - 1)));
    }
    if (m && m.kind === "scroll") {
      const from = await K.insist("scrollY", () => page.evaluate(() => Math.round(window.scrollY * 2) / 2), 12000);
      const cap = await K.insist("maxScroll", () => K.maxScroll(page), 12000);
      const to = Math.min(m.to, cap);
      if (m.to > cap + 2) console.log(`    (scroll ${m.to} clamped to ${cap})`);
      const dist = Math.abs(to - from), sign = to >= from ? 1 : -1;
      const e = Math.round(0.35 * FPS);
      const want = Math.max(1, Math.round(m.secs * FPS));
      // Whole device pixels a frame through the middle of the move: the
      // scroller rounds to half a CSS pixel at a 2x device scale, so anything
      // else would alternate between two steps and read as a stutter.
      const step = Math.max(0.5, Math.round((dist / Math.max(1, want - e)) * 2) / 2);
      let flat = Math.max(1, Math.round(dist / step) - e);
      const nm = Math.min(n, flat + 2 * e);
      const r = K.ramp(nm, e);
      const lead = Math.min(Math.round((m.lead != null ? m.lead : 0.8) * FPS), Math.max(0, n - nm));
      for (let f = 0; f < n; f++) {
        const j = f - lead;
        const t = j < 0 ? 0 : j >= nm ? 1 : r[j];
        scrollOf.push(Math.round((from + sign * dist * t) * 2 + 1e-6) / 2);
      }
      const mid = scrollOf.slice(lead + e, lead + nm - e);
      const d = mid.slice(1).map((v, j) => Math.abs(v - mid[j]));
      if (d.length) console.log(`    scroll ${from}->${to} over ${nm}f, flat step ${Math.min(...d)}-${Math.max(...d)} px/frame`);
    }
    if (m && m.kind === "rotate") {
      const nm = Math.min(n, Math.round(m.secs * FPS));
      const hold = Math.round((m.hold || 0) * FPS);
      const half = m.back ? Math.round((nm - hold) / 2) : nm - hold;
      const backN = m.back ? nm - half - hold : 0;
      const lead = Math.min(Math.round(0.6 * FPS), Math.max(0, n - nm));
      const ys = [];
      const fwd = K.ramp(half, Math.round(0.3 * FPS));
      for (let f = 0; f < half; f++) ys.push(m.from + (m.to - m.from) * fwd[f]);
      for (let f = 0; f < hold; f++) ys.push(m.to);
      if (backN > 0) {
        const rev = K.ramp(backN, Math.round(0.3 * FPS));
        for (let f = 0; f < backN; f++) ys.push(m.to + (m.from - m.to) * rev[f]);
      }
      for (let f = 0; f < n; f++) {
        const j = f - lead;
        yawOf.push(j < 0 ? ys[0] : j >= ys.length ? ys[ys.length - 1] : ys[j]);
      }
      const dd = yawOf.slice(lead + 10, lead + half - 10);
      const st = dd.slice(1).map((v, j) => Math.abs(v - dd[j]));
      if (st.length) console.log(`    rotate ${m.key} ${m.from}->${m.to}, flat step ` +
        `${Math.min(...st).toFixed(5)}-${Math.max(...st).toFixed(5)} rad`);
    }

    /* ---- capture ---- */
    const out = path.join(SEG, String(i).padStart(3, "0") + ".mp4");
    const enc = K.encoder(out);
    if (prevShot && transF) await page.evaluate((u) => window.__ov.setPrev(u), prevShot);
    let last = null, lastZoom = 1;
    for (let f = 0; f < n; f++) {
      if (clickFrame != null && f === clickFrame) await clickDo();
      if (scrollOf.length) await K.scrollTo(page, scrollOf[f]);
      if (yawOf.length) {
        await K.insist("pose", () => page.evaluate((pose) => {
          window.__demoPose = pose;
          try { document.fonts.dispatchEvent(new Event("loadingdone")); } catch (e) { /* no fonts api */ }
        }, { key: m.key, yaw: yawOf[f] }), 12000);
      }
      // The overlay step and the scroll read share one round trip; the clip
      // rectangle is in document coordinates, so it needs the scroll offset.
      let sc = await K.insist("overlay step", () => page.evaluate((k) => {
        window.__ov.step(k);
        return { x: window.scrollX, y: window.scrollY };
      }, f), 12000);
      await clock.frame();
      // A constant 2 % crop reserves a 19 px margin inside the viewport for the
      // drift to move within, so the clip never asks for pixels the page has
      // not laid out.
      const zoom = (zoomOf.length ? zoomOf[f] : 1) * 1.02;
      lastZoom = zoom;
      // A screenshot that will not answer is sometimes unstuck by another tick
      // of the clock: the compositor is waiting for a frame it will only get
      // when virtual time moves. If that does not help either, the renderer
      // itself has stopped answering — the operator workspace does this about
      // six seconds in — and the only way back is a reload. The shot resumes
      // from the frame it was on, so nothing is repeated and nothing is lost.
      const [dx, dy] = drift(f);
      try {
        last = await K.shoot(cdp, zoom, sc.x, sc.y, dx, dy);
      } catch (e) {
        try {
          console.log("    (screenshot stalled at frame " + f + "; ticking and retrying)");
          await clock.frame();
          last = await K.shoot(cdp, zoom, sc.x, sc.y, dx, dy);
        } catch (e2) {
          console.log("    (renderer wedged at frame " + f + "; reloading and resuming)");
          if (s.pre) await s.pre(c);
          await installPose();
          await K.insist("overlay re-begin", () => page.evaluate(
            (p) => window.__ov.begin(p), { dur: n, prog, items }), 15000);
          if (prevShot && transF) await page.evaluate((u) => window.__ov.setPrev(u), prevShot);
          if (scrollOf.length) await K.scrollTo(page, scrollOf[f]);
          sc = await K.insist("overlay step", () => page.evaluate((k) => {
            window.__ov.step(k);
            return { x: window.scrollX, y: window.scrollY };
          }, f), 12000);
          await clock.frame();
          last = await K.shoot(cdp, zoom, sc.x, sc.y, dx, dy);
        }
      }
      await enc.write(last);
    }
    await enc.close();
    if (yawOf.length) await K.insist("pose reset", () => page.evaluate(() => { window.__demoPose = null; try { document.fonts.dispatchEvent(new Event("loadingdone")); } catch (e) {} }), 12000).catch(() => {});
    await K.insist("overlay clear", () => page.evaluate(() => window.__ov.clear()), 12000).catch(() => {});
    // `Memory.forciblyPurgeJavaScriptMemory` was tried here and removed: on the
    // pages that carry a WebGL scene it leaves the renderer unable to answer an
    // evaluate for minutes afterwards. Dropping the outgoing-frame bitmap in
    // `__ov.clear()` is what actually mattered.
    prevShot = "data:image/jpeg;base64," + last.toString("base64");

    console.log(`${String(i + 1).padStart(2, "0")}/${SHOTS.length}  ${(n / FPS).toFixed(2)}s  ` +
      `${((Date.now() - t0) / 1000).toFixed(0)}s  ${(s.cap ? K.stripTags(s.cap[0]) : (s.card ? s.card.big.replace(/\n/g, " ") : "")).slice(0, 48)}`);
  }

  const mf = path.join(WORK, "tour.json");
  const prior = fs.existsSync(mf) ? JSON.parse(fs.readFileSync(mf, "utf8")) : null;
  fs.writeFileSync(mf, JSON.stringify({ fps: FPS, width: K.W, height: K.H, shots: manifest }, null, 2));
  if (prior && prior.shots.length !== manifest.length) console.log("  (manifest length changed)");

  await page.close(); await browser.close();
  console.log(external.size ? "EXTERNAL REQUESTS:\n" + [...external].join("\n") : "no external requests");
  console.log("segments in", SEG);
})().catch((e) => { console.error("FAIL", e); process.exit(1); });
