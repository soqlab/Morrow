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
const WORK = path.resolve(argOf("--work", path.join(os.tmpdir(), "airlock-3min")));
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

const SHOTS = [
  /* ================= ACT ONE · the problem ================= 66 beats ==== */
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
    // Racks sharp and hands the frame to the product.
    beats: 8, trans: "push", pre: async (c) => { await c.nav("overview"); await c.scroll(0); },
    scrim: { level: 0.30, grad: "bottom", blur: [5, 0], blurB: 90 }, dolly: [1.0, 1.03],
    big: { lines: ["Example Financial Group.", `<span class="${I}">38</span> endpoints.`,
      `<span class="${A}">$3.33M</span> modelled exposure.`],
      cls: ["md", "md", "md"], mode: "rise", inF: 14, stagger: 7 },
    pos: "low",
    // The Overview's posture row is `.metricRow`, not the `.kpi` tiles the
    // other workspaces use.
    counts: [{ sel: ".metricRow b", nth: 0, at: [0.3, 2.2] },
      { sel: ".metricRow b", nth: 2, at: [0.5, 2.6] }],
    calls: [{ sel: ".metricRow", shape: "bracket", label: "INVENTORY · 38 ASSETS", side: "below", at: [2.4, 3.8] }],
    verify: [{ sel: ".metricRow", has: "38" },
      { sel: ".metricRow", text: "Modeled exposure", has: "$3.33M" }],
  },
  {
    beats: 7, trans: "wiperight", pre: async (c) => { await c.nav("qday"); await c.scroll(980); },
    scrim: SHOW_SOFT, dolly: [1.03, 1.0],
    big: { lines: ["And the deadlines", "are published."], cls: ["md", "md"], mode: "rise", inF: 14, stagger: 6 },
    pos: "low",
    calls: [{ sel: ".card.lift", text: "Migration milestones", shape: "bracket",
      label: "THE PRODUCT'S OWN MILESTONE LIST", side: "right", at: [1.4, 3.4] }],
  },
  {
    beats: 8, trans: null, scrim: { level: 0.50 }, dolly: [1.0, 1.035],
    big: { lines: ['<span class="plate">2030</span>', "CNSA 2.0 · published target"],
      cls: ["xl", "mono"], mode: "depth", inF: 14, stagger: 7, justify: "center" },
    verify: [{ sel: ".card.lift", text: "Migration milestones", has: "2030" }],
  },
  {
    beats: 8, trans: null, scrim: { level: 0.50 }, dolly: [1.035, 1.0],
    big: { lines: ['<span class="plate">2035</span>', "NSM-10 · published target"],
      cls: ["xl", "mono"], mode: "depth", inF: 14, stagger: 7, justify: "center" },
    verify: [{ sel: ".card.lift", text: "Migration milestones", has: "2035" }],
  },
  {
    // A reveal, not an orbit: the distribution turns once and stops. No dolly.
    beats: 8, trans: "wipeup", pre: async (c) => { await c.nav("qday"); await c.scroll(640); },
    reveal: { key: "area", yaw: [-0.30, 0.16], secs: 3.0, lead: 0.5 },
    scrim: SHOW,
    big: { lines: ["It models when, not if.", `Model Q-Day <span class="${I}">2031</span>.`], cls: ["md", "md"], mode: "rise", inF: 14, stagger: 6 },
    pos: "low",
  },

  /* ================= ACT TWO · discovery ================== 55 beats ==== */
  {
    beats: 8, trans: "push", pre: async (c) => { await c.nav("scans"); },
    scrim: SHOW, dolly: [1.0, 1.04],
    big: { lines: ["It starts with what", `you <span class="${I}">actually run</span>.`], cls: ["md", "md"], mode: "rise", inF: 14, stagger: 6 },
    pos: "low",
    calls: [{ sel: ".opsPanel", shape: "bracket", label: "LIVE SCAN · 38 ENDPOINTS", side: "above", at: [1.0, 3.6] }],
  },
  {
    beats: 7, trans: null, motion: { kind: "scroll", to: 907, secs: 2.6, lead: 0.3 },
    scrim: SHOW,
    big: { lines: [`<span class="${I}">Eight</span> scan runs across <span class="${I}">five</span> months.`], cls: ["md"], mode: "wipe", inF: 12 },
    pos: "low",
    verify: [{ sel: ".card.lift", text: "Recent scans", has: "8 most recent" }],
  },
  {
    beats: 8, trans: "wipeleft", scrim: STORY([11, 7]), dolly: [1.04, 1.0],
    big: { lines: ["Every handshake is recorded:",
      "protocol, cipher suite, key algorithm, key size."],
      cls: ["md", "tag"], mode: "rise", inF: 16, stagger: 8 },
  },
  {
    beats: 8, trans: "push", pre: async (c) => { await c.nav("assets"); },
    scrim: { level: 0.30, grad: "bottom", blur: [4, 0], blurB: 80 }, dolly: [1.0, 1.035],
    big: { lines: [`<span class="${I}">38</span> assets,`, "each with an owner."], cls: ["md", "md"], mode: "rise", inF: 14, stagger: 6 },
    pos: "low",
    counts: [{ sel: ".kpi.lift", nth: 0, at: [0.3, 2.3] }],
    calls: [{ sel: ".kpi.lift", nth: 0, shape: "box", label: "38 ASSETS · 11 OWNERS", side: "below", at: [2.0, 3.8] }],
    verify: [{ sel: ".kpi.lift", nth: 0, has: "38" }],
  },
  {
    beats: 8, trans: null, motion: { kind: "scroll", to: 600, secs: 2.8, lead: 0.3 },
    scrim: SHOW,
    big: { lines: ["RSA 2048 and 3072.", "Elliptic curve P-256 and P-384.",
      `One gateway already on a <span class="${G}">hybrid key exchange</span>.`],
      cls: ["md", "md", "tag"], mode: "rise", inF: 14, stagger: 7 },
    pos: "low",
  },
  {
    beats: 8, trans: "wiperight", scrim: STORY([12, 8]), dolly: [1.035, 1.0],
    big: { lines: ["Key type and size are the whole question.",
      "RSA and elliptic curve both fall to the same algorithm."],
      cls: ["md", "tag"], mode: "rise", inF: 16, stagger: 8 },
  },
  {
    beats: 8, trans: "push", pre: async (c) => { await c.nav("assets"); await c.scroll(1100); },
    scrim: SHOW, dolly: [1.0, 1.035],
    big: { lines: ["And how long the data", "has to stay secret."], cls: ["md", "md"], mode: "rise", inF: 14, stagger: 6 },
    pos: "low",
  },

  /* ================= ACT THREE · exposure ================= 72 beats ==== */
  {
    beats: 8, trans: "wipeup", pre: async (c) => { await c.nav("hndl"); },
    scrim: { level: 0.30, grad: "bottom", blur: [5, 0], blurB: 80 }, dolly: [1.035, 1.0],
    big: { lines: [`All <span class="${I}">38</span> priced`, "by what the traffic is worth."], cls: ["md", "md"], mode: "rise", inF: 14, stagger: 6 },
    pos: "low",
    calls: [{ sel: ".vendSummary", shape: "bracket", label: "RISK TIERS · 38 ASSETS", side: "below", at: [1.6, 3.8] }],
  },
  {
    beats: 9, trans: "wipeleft", scrim: STORY([12, 8]), dolly: [1.0, 1.04],
    big: { lines: ["Secrecy lifetime, plus the odds the key breaks,",
      "gives the year that traffic becomes readable."],
      cls: ["md", "tag"], mode: "rise", inF: 16, stagger: 9 },
  },
  {
    beats: 8, trans: "push", pre: async (c) => { await c.nav("hndl"); await c.scroll(470); },
    scrim: SHOW, dolly: [1.04, 1.0],
    big: { lines: ["Ranked by modelled exposure,", "not by a severity label."], cls: ["md", "md"], mode: "rise", inF: 14, stagger: 6 },
    pos: "low",
    calls: [{ sel: "#view table tbody tr", nth: 0, shape: "box", tone: "warm",
      label: "ldap.internal.example · RSA-2048 · 15-YEAR SECRECY · $2.10M", side: "below", at: [1.4, 3.8] }],
    verify: [{ sel: "#view table tbody tr", nth: 0, has: "RSA-2048" }],
  },
  {
    beats: 8, trans: null, motion: { kind: "scroll", to: 820, secs: 2.8, lead: 0.3 },
    scrim: SHOW,
    big: { lines: ["Then the model draws it."], cls: ["md"], mode: "wipe", inF: 12 },
    pos: "low",
  },
  {
    // Hero one: the exposure timeline turns once, camera still.
    beats: 12, trans: "fade", pre: async (c) => { await c.scroll(820); },
    reveal: { key: "timeline", yaw: [-0.34, 0.30], secs: 4.6, lead: 0.7 },
    scrim: { level: 0.24, grad: "bottom" },
    big: { lines: ["Amber is captured, still sealed.", `<span class="${A}">Red is the same traffic, readable.</span>`],
      cls: ["md", "tag"], mode: "rise", inF: 16, stagger: 8 },
    pos: "low",
  },
  {
    // Hero two: the one push through the wall. Chart held, camera moves.
    beats: 10, trans: null, dolly: [1.0, 1.16], truckScale: 0.35,
    scrim: { level: 0.22, grad: "bottom" },
    big: { lines: ["The wall is model Q-Day.", `<span class="${I}">2031</span>, on this estate's own numbers.`],
      cls: ["md", "tag"], mode: "rise", inF: 16, stagger: 8 },
    pos: "low",
  },
  {
    beats: 9, trans: "wiperight",
    pre: async (c) => { await c.hover(".c3d[data-c3d='curves'] canvas", 0.55, 0.45); },
    reveal: { key: "curves", yaw: [0.30, -0.18], secs: 3.4, lead: 0.5 },
    scrim: SHOW,
    big: { lines: ["One curve per algorithm.", `RSA-2048 crosses fifty per cent in <span class="${A}">2031</span>.`],
      cls: ["md", "tag"], mode: "rise", inF: 14, stagger: 7 },
    pos: "low",
  },
  {
    beats: 8, trans: "wipeleft", scrim: STORY([12, 9]), dolly: [1.0, 1.035],
    big: { lines: ["Every modelled figure says so on the chart.",
      "Nothing estimated is shown as measurement."],
      cls: ["md", "tag"], mode: "rise", inF: 16, stagger: 8 },
  },

  /* ================= ACT FOUR · evidence ================== 40 beats ==== */
  {
    beats: 8, trans: "push", pre: async (c) => { await c.nav("cbom"); },
    scrim: { level: 0.30, grad: "bottom", blur: [5, 0], blurB: 80 }, dolly: [1.035, 1.0],
    big: { lines: ["A cryptographic", "bill of materials."], cls: ["md", "md"], mode: "rise", inF: 14, stagger: 6 },
    pos: "low",
    counts: [{ sel: ".vendSummary", at: [0.3, 2.4] }],
    verify: [{ sel: ".vendSummary", has: "87 components" }],
  },
  {
    beats: 8, trans: null, scrim: SHOW, dolly: [1.0, 1.035],
    big: { lines: [`<span class="${I}">87</span> components catalogued.`, `<span class="${G}">Two</span> already post-quantum.`],
      cls: ["md", "md"], mode: "rise", inF: 14, stagger: 6 },
    pos: "low",
    calls: [{ sel: ".vendSummary", shape: "bracket", tone: "good",
      label: "CYCLONEDX 1.6 · GENERATED FROM THE SCANS", side: "below", at: [1.4, 3.8] }],
  },
  {
    beats: 8, trans: "wipeup", scrim: STORY([12, 8]), dolly: [1.035, 1.0],
    big: { lines: ["An auditor does not take your word for it.",
      "This is the document they read instead."],
      cls: ["md", "tag"], mode: "rise", inF: 16, stagger: 8 },
  },
  {
    // The Governance workspace is filmed on the tab it opens on. Its Compliance
    // tab builds a control-mapping panel that reliably stops Chrome answering a
    // screenshot — on the GPU path and on SwiftShader — and the figures this
    // beat needs are on the KPI row either way.
    beats: 8, trans: "push", pre: async (c) => { await c.load("/ui/#governance"); },
    scrim: SHOW, dolly: [1.0, 1.035],
    big: { lines: [`<span class="${I}">Four</span> control frameworks.`, `<span class="${I}">Seven</span> regulatory regimes.`],
      cls: ["md", "md"], mode: "rise", inF: 14, stagger: 6 },
    pos: "low",
    calls: [{ sel: ".kpi.lift", text: "Compliance frameworks", shape: "box",
      label: "MAPPED TO THE FRAMEWORKS YOU ARE JUDGED ON", side: "below", at: [1.4, 3.8] }],
    verify: [{ sel: ".kpi.lift", text: "Compliance frameworks", has: "4" },
      { sel: ".kpi.lift", text: "Regulatory regimes", has: "7" }],
  },
  {
    beats: 8, trans: "wipeleft", scrim: SHOW, dolly: [1.035, 1.0],
    big: { lines: [`<span class="${I}">Four</span> evidence packs,`, "timestamped and hash-chained."],
      cls: ["md", "md"], mode: "rise", inF: 14, stagger: 6 },
    pos: "low",
    calls: [{ sel: ".kpi.lift", text: "Evidence packs", shape: "box",
      label: "EVIDENCE PACKS", side: "below", at: [1.2, 3.6] }],
    verify: [{ sel: ".kpi.lift", text: "Evidence packs", has: "4" }],
  },

  /* ============ ACT FIVE · action and assurance =========== 70 beats ==== */
  {
    beats: 8, trans: "push", pre: async (c) => { await c.nav("remediation"); },
    scrim: SHOW, dolly: [1.0, 1.04],
    big: { lines: ["Finding the cryptography", "is the easy part."], cls: ["md", "md"], mode: "rise", inF: 14, stagger: 6 },
    pos: "low",
    calls: [{ sel: ".card.lift", text: "Pipeline", shape: "bracket", label: "7 OPEN · 9 TRACKED", side: "right", at: [1.2, 3.8] }],
    verify: [{ sel: ".kpi.lift", nth: 0, has: "7" }],
  },
  {
    beats: 8, trans: null, scrim: SHOW, dolly: [1.04, 1.0],
    big: { lines: ["Suggested. Approved.", "Pull request.", `<span class="${G}">Verified closed.</span>`],
      cls: ["md", "md", "md"], mode: "rise", inF: 14, stagger: 7 },
    pos: "low",
  },
  {
    beats: 9, trans: "wiperight", scrim: STORY([12, 8]), dolly: [1.0, 1.035],
    big: { lines: ["A fix is not closed because someone said so.",
      "It is closed because a later scan proves it."],
      cls: ["md", "tag"], mode: "rise", inF: 16, stagger: 9 },
  },
  {
    beats: 8, trans: "push", pre: async (c) => { await c.load("/ui/#graph"); await c.scroll(120); },
    scrim: { level: 0.30, grad: "bottom", blur: [5, 0], blurB: 80 }, dolly: [1.035, 1.0],
    big: { lines: ["Before you touch an authority,", "know what hangs off it."], cls: ["md", "md"], mode: "rise", inF: 14, stagger: 6 },
    pos: "low",
    calls: [{ sel: ".kpi.lift", text: "Leaf certificates", shape: "box", label: "LEAF CERTIFICATES", side: "below", at: [1.4, 3.8] }],
    verify: [{ sel: ".kpi.lift", text: "Leaf certificates", has: "38" }],
  },
  {
    beats: 8, trans: null, reveal: { key: "bar", yaw: [-0.26, 0.20], secs: 3.0, lead: 0.4 },
    scrim: SHOW,
    big: { lines: [`Two roots. <span class="${I}">38</span> leaf certificates.`, "Fifty-three nodes in the graph."],
      cls: ["md", "tag"], mode: "rise", inF: 14, stagger: 6 },
    pos: "low",
    verify: [{ sel: ".kpi.lift", text: "Graph nodes", has: "53" }],
  },
  {
    beats: 8, trans: "wipeup", pre: async (c) => { await c.nav("canaries"); await c.scroll(250); },
    scrim: SHOW, dolly: [1.0, 1.035],
    big: { lines: ["Five canary keys", "at five strengths."], cls: ["md", "md"], mode: "rise", inF: 14, stagger: 6 },
    pos: "low",
    calls: [{ sel: ".sec", text: "Tripwire ladder", shape: "bracket", tone: "good",
      label: "ALPHA → OMEGA · NO TIER HAS TRIPPED", side: "right", at: [1.2, 3.8] }],
    verify: [{ sel: ".sec", text: "Tripwire ladder", has: "No tier has tripped" }],
  },
  {
    beats: 9, trans: "wipeleft", scrim: STORY([12, 8]), dolly: [1.035, 1.0],
    big: { lines: ["The first one to trip tells you",
      "how far quantum capability has actually reached."],
      cls: ["md", "tag"], mode: "rise", inF: 16, stagger: 9 },
  },
  {
    beats: 6, trans: "push", pre: async (c) => { await c.nav("board"); },
    reveal: { key: "gauge", yaw: [-0.26, 0.18], secs: 2.2, lead: 0.3 },
    scrim: SHOW,
    big: { lines: ["One number for the board."], cls: ["md"], mode: "rise", inF: 13 },
    pos: "low",
    counts: [{ sel: ".kpi.lift", nth: 0, at: [0.3, 2.2] }],
    verify: [{ sel: ".kpi.lift", nth: 0, has: "/100" }],
  },
  {
    beats: 6, trans: null, scrim: SHOW, dolly: [1.0, 1.035],
    big: { lines: ["With every weight shown."], cls: ["md"], mode: "rise", inF: 13 },
    pos: "low",
    calls: [{ sel: ".card.lift", text: "Score composition", shape: "bracket", label: "EVERY WEIGHT, SHOWN", side: "right", at: [0.8, 2.9] }],
  },

  /* =============== ACT SIX · the pilot and close ========== 57 beats ==== */
  {
    beats: 8, trans: "push", pre: async (c) => { await c.nav("overview"); await c.scroll(0); },
    scrim: { level: 0.34, grad: "bottom", blur: [6, 0], blurB: 80 }, dolly: [1.05, 1.0],
    big: { lines: ["Start narrow."], cls: ["md"], mode: "rise", inF: 14 },
    pos: "low",
  },
  {
    beats: 8, trans: null, scrim: STORY([9, 7]), dolly: [1.0, 1.03],
    big: { lines: ["Six to eight weeks.", "One organisation."], cls: ["md", "md"], mode: "rise", inF: 15, stagger: 7 },
  },
  {
    beats: 8, trans: null, scrim: STORY([7, 6]), dolly: [1.03, 1.0],
    big: { lines: ["Three to five", "critical applications."], cls: ["md", "md"], mode: "rise", inF: 15, stagger: 7 },
  },
  {
    beats: 9, trans: "wipeup", scrim: STORY([6, 5]), dolly: [1.0, 1.03],
    big: { lines: ["One approved inventory.",
      "One fix carried to verified closure.",
      "One evidence pack an auditor can read."],
      cls: ["md", "tag", "tag"], mode: "rise", inF: 16, stagger: 9 },
  },
  {
    beats: 12, trans: "fade", pre: async (c) => { await c.nav("overview"); await c.scroll(0); },
    dolly: [1.0, 1.03], scrim: { level: 0.76, blur: [5, 5] },
    card: { kick: "Morrow", big: "Cryptographic\ngovernance.", ruleW: 470,
      sub: "For the post-quantum migration.", scrim: null },
  },
  {
    beats: 12, trans: "fade", scrim: { level: 0.78, blur: [5, 5] }, dolly: [1.03, 1.0],
    // No address here: inventing one, even under a reserved TLD, would be the
    // one claim in the film that nothing on screen supports.
    big: { lines: ["Controlled pilot.",
      "Six to eight weeks, on your own estate.",
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
      await clock.frame();
      const zoom = zoomOf[f] * BASE_Z;
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
      `${((Date.now() - t0) / 1000).toFixed(0)}s  truck ${perFrame.toFixed(2)}px/f  ` +
      `${(s.big ? K.stripTags(s.big.lines[0]) : (s.card ? s.card.kick : "")).slice(0, 40)}`);
  }

  fs.writeFileSync(path.join(WORK, "film.json"),
    JSON.stringify({ fps: FPS, beat: BEAT, bpm: 120, width: K.W, height: K.H, shots: manifest }, null, 2));
  await page.close(); await browser.close();
  console.log(external.size ? "EXTERNAL REQUESTS:\n" + [...external].join("\n") : "no external requests");
  console.log("segments in", SEG);
})().catch((e) => { console.error("FAIL", e); process.exit(1); });
