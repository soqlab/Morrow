// The live instrument at / and its views, in a real browser.
//
// Replaces landing-motion-smoke.js, which checked the decorative landing scene, its motion toggle
// and its status poll. That page was retired; what is asserted now is the opposite promise:
//   - nothing animates on its own: after load, no running animation anywhere on the page;
//   - every request the page makes goes to this origin;
//   - the one input recognises what is typed (domain, algorithm, CVE, commit) and the address is
//     the interface (/<domain> opens that domain's view);
//   - the technicality dial changes the wording and is kept in the URL;
//   - the plain version works with JavaScript switched off;
//   - no horizontal overflow at phone width; no JavaScript errors.
const { chromium } = require("../.tools/video/node_modules/playwright");
const assert = require("node:assert/strict");
const base = (process.env.MORROW_E2E_BASE_URL || "http://127.0.0.1:8001").replace(/\/$/, "");
const origin = new URL(base).origin;

const SMOKE_DOMAIN = "harvest-smoke.example";
const SMOKE_GRADE = {
  domain: SMOKE_DOMAIN, scanned_at: new Date().toISOString(), cached: false, grade: "C",
  summary: "classical", summaries: { executive: "classical", cryptographer: "x25519 only" },
  tls: { versions: { "1.3": true, "1.2": true, "1.1": false, "1.0": false }, negotiated: "TLSv1.3", untested: [] },
  key_exchange: { group: "x25519", post_quantum: false, hybrid: false, offered_pq_groups_accepted: [], observed: true },
  certificate: { key_type: "EC", key_bits: 256, signature_algorithm: "ecdsa-with-SHA256", not_after: "2027-01-01T00:00:00Z", issuer: "CN=Test", verified: true },
  forward_secrecy: true, server_software: "nginx", platform: "nginx",
  exposure: { recorded_traffic_at_risk: true, decrypt_year_low: 2035, decrypt_year_high: 2040, basis: "basis", source_url: "https://globalriskinstitute.org/" },
  fixes: [{ title: "Turn on X25519MLKEM768", snippet: "ssl_ecdh_curve X25519MLKEM768:X25519;", notes: "", requires: "OpenSSL 3.5", applies_to: "nginx" }],
  reasons: ["TLS 1.3 with classical key exchange only (x25519)."], rubric_version: "test", connections: 9, notes: [],
};
const SMOKE_EXPOSURE = {
  domain: SMOKE_DOMAIN, checked_at: new Date().toISOString(), cached: false,
  homepage: { url: `https://${SMOKE_DOMAIN}/`, read: true, notes: [] },
  own: { grade: "C", post_quantum: false, key_exchange: "x25519" },
  services: [
    { host: "js.stripe.com", role: "payment", vendor: "Stripe", via: "script on the homepage", status: "classical", key_exchange: "x25519", readable_from: 2035, fix: "Ask Stripe when js.stripe.com will offer X25519MLKEM768." },
    { host: "fonts.googleapis.com", role: "fonts", vendor: "Google Fonts", via: "stylesheet on the homepage", status: "pq", key_exchange: "X25519MLKEM768", readable_from: null, fix: "Nothing to ask for." },
  ],
  counts: { found: 2, probed: 2, exposed: 1, graded: 2, over_cap: 0 }, probed: 2, limits: { max_hosts: 12 },
  summaries: { plain: "You're not ready yet, and neither is your payment provider (js.stripe.com).",
    standard: "You're ready, but your payment provider isn't (js.stripe.com).", expert: "1/2 graded third-party hosts are classical." },
};
async function routeDomain(page) {
  await page.route(`**/api/public/grade/${SMOKE_DOMAIN}*`, (r) => r.fulfill({ json: SMOKE_GRADE }));
  await page.route(`**/api/public/history/${SMOKE_DOMAIN}*`, (r) => r.fulfill({ json: [] }));
  await page.route(`**/api/public/exposure/${SMOKE_DOMAIN}*`, (r) => r.fulfill({ json: SMOKE_EXPOSURE }));
}

const SMOKE_TOKEN = "smokeTokenAbcdefghijklmnop";
const SMOKE_REPORT = {
  id: "r1", name: "", status: "done", total: 3, done: 3, pending: 0, graded: 2, exposed: 1,
  grades: { A: 1, B: 0, C: 0, D: 0, E: 0, F: 1 },
  summaries: { plain: "1 of your 2 checked vendors would let today's traffic be read later. Worst: payroll.example (RSA key exchange). 1 could not be checked.",
    standard: "1 of your 2 checked vendors would let today's traffic be read later. Worst: payroll.example (RSA key exchange). 1 could not be checked.",
    expert: "1/2 graded below B; A×1 F×1. Worst: payroll.example, grade F (RSA key exchange). 1 could not be checked." },
  vendors: [
    { domain: "payroll.example", status: "graded", grade: "F", key_exchange: "", post_quantum: false, checked_at: new Date().toISOString(), why: "RSA key exchange", readable_from: 2035, detail: "", exposed: true, page: "/payroll.example",
      note: "Subject: Post-quantum key exchange on payroll.example\n\nHello,\n\nA public check found that payroll.example accepts RSA key exchange.\nhttps://morrow.example/payroll.example\n\nThank you." },
    { domain: "mail.example", status: "graded", grade: "A", key_exchange: "X25519MLKEM768", post_quantum: true, checked_at: new Date().toISOString(), why: "post-quantum key exchange (X25519MLKEM768)", readable_from: null, detail: "", exposed: false, page: "/mail.example" },
    { domain: "gone.example", status: "unreachable", grade: null, key_exchange: null, post_quantum: null, checked_at: new Date().toISOString(), why: "", readable_from: null, detail: "did not answer", exposed: null, page: "/gone.example" },
  ],
  created_at: new Date().toISOString(), updated_at: new Date().toISOString(), finished_at: new Date().toISOString(),
  expires_at: "2099-01-01T00:00:00Z", saved: false, interval_days: null, next_check_at: null, history: [],
  basis: "basis", sends_nothing: "Morrow sends nothing to your vendors.",
};
const SMOKE_CHANGES = {
  title: "What changed", count: 2, counts: { ready: 1, not_ready: 0, listed: 0, sector: 1 }, sector: null, sectors: [["finance", "Banks & payments"]],
  rubric_version: "test", generated_at: new Date().toISOString(), rules: { named: "n", changes: "c", sectors: "s", measured: "m" },
  events: [
    { kind: "ready", at: new Date().toISOString(), domain: "acme.example", named: true, page: "/acme.example", sector: "unclassified", sector_name: "Other popular sites", title: "acme.example became post-quantum ready: grade C to A (checked today)." },
    { kind: "sector", at: new Date().toISOString(), named: false, page: "/report/finance", sector: "finance", sector_name: "Banks & payments", became_ready: 2, dropped: 0, title: "2 sites in Banks & payments became post-quantum ready in the week of 2026-11-09. Sites in the sector lists are not named." },
  ],
};
const SMOKE_SECTOR = {
  id: "finance", name: "Banks & payments", url: "/report/finance", csv: "/api/public/report/finance.csv", as_of: new Date().toISOString(), rubric_version: "test",
  sample: { listed: 100, graded: 90, unreachable: 4, not_graded_yet: 6, opted_out_left_out: 0 }, ready: 31, ready_share: 0.3444, pq_key_exchange: 31,
  grades: { A: 25, B: 6, C: 40, D: 12, E: 4, F: 3 },
  trend: [{ week: "2026-08-03", graded: 80, ready: 17, share: 0.2125, grades: {} }, { week: "2026-11-02", graded: 90, ready: 31, share: 0.3444, grades: {} }],
  comparison: { week: "2026-08-03", month: "August 2026", share: 0.2125, graded: 80, ready: 17, change: 0.1319 },
  headline: { plain: "34.4% of the Banks & payments sites Morrow watches are post-quantum ready, up from 21.3% in August 2026.",
    standard: "34.4% (31 of 90) of the Banks & payments sites Morrow watches are post-quantum ready (grade A or B), up from 21.3% in August 2026.",
    expert: "Banks & payments: 31/90 graded A or B." },
  methodology: { who: "w", sources: ["s"], list: "l", measured: "m", ready: "r", cadence: "c", not_measured: ["n"], names: "No site is named." },
};
async function routeReports(page) {
  await page.route(`**/api/public/vendors/report/${SMOKE_TOKEN}`, (r) => r.fulfill({ json: SMOKE_REPORT }));
  await page.route("**/api/public/changes?*", (r) => r.fulfill({ json: SMOKE_CHANGES }));
  await page.route("**/api/public/report/finance", (r) => r.fulfill({ json: SMOKE_SECTOR }));
}

async function main() {
  const browser = await chromium.launch({ headless: true });
  const errors = [];
  const foreign = [];
  try {
    const context = await browser.newContext({ viewport: { width: 1280, height: 860 } });
    const page = await context.newPage();
    page.on("pageerror", (e) => errors.push(String(e)));
    page.on("request", (r) => { const u = r.url(); if (!u.startsWith(origin) && !u.startsWith("data:")) foreign.push(u); });

    await page.goto(`${base}/`, { waitUntil: "networkidle" });
    await page.locator("#home-q").waitFor();
    // Signed out it shows public counts; with a workspace (CI runs without sign-in) it reads the estate.
    await page.waitForFunction(() => document.querySelector("#home-stats .reading, #home-stats .i-empty, #home-estate p, #home-estate .scrub") !== null, null, { timeout: 30000 });
    const running = await page.evaluate(() => document.getAnimations().filter((a) => a.playState === "running").length);
    assert.equal(running, 0, "something animates on its own after load");
    assert.ok(await page.locator("#i-build").innerText(), "the commit line is empty");

    await page.fill("#home-q", "https://www.Example.com/path");
    await page.locator('.i-opt[data-kind="domain"]').first().waitFor();
    assert.match(await page.locator(".i-opt").first().innerText(), /example\.com/i);
    await page.fill("#home-q", "kyber");
    assert.equal(await page.locator(".i-opt").first().getAttribute("href"), "/algorithms/ml-kem");
    await page.fill("#home-q", "CVE-2014-0160");
    assert.equal(await page.locator(".i-opt").first().getAttribute("data-kind"), "cve");
    await page.fill("#home-q", "deadbeef1");
    assert.equal(await page.locator(".i-opt").first().getAttribute("data-kind"), "commit");

    await page.keyboard.press("Escape");
    await page.locator("body").click();
    await page.keyboard.press("Control+k");
    await page.locator("#pal-q").waitFor();
    await page.keyboard.type("league");
    await page.keyboard.press("Enter");
    await page.waitForURL(`${base}/league`);

    await page.goto(`${base}/algorithms/x25519`, { waitUntil: "networkidle" });
    const standard = await page.locator("#say").innerText();
    await page.locator('#i-dial button[data-d="plain"]').click();
    assert.ok(page.url().includes("depth=plain"), "the dial is not kept in the URL");
    const plain = await page.locator("#say").innerText();
    assert.notEqual(plain, standard, "the dial did not change the wording");

    await page.goto(`${base}/trust`, { waitUntil: "networkidle" });
    await page.locator("#tr-req p").first().waitFor({ timeout: 30000 });
    assert.match(await page.locator("#tr-req").innerText(), /went to/);

    // A domain view, its API answered here (CI has nothing it may grade): the harvest clock answers
    // as its dials move, and the outside services are listed worst first with the answer on top.
    await routeDomain(page);
    await page.goto(`${base}/${SMOKE_DOMAIN}?depth=standard&keep=15`, { waitUntil: "networkidle" });
    await page.locator("#hv-say").waitFor({ timeout: 15000 });
    const year = new Date().getUTCFullYear();
    let clock = await page.locator("#hv-say").innerText();
    assert.match(clock, /could be read around 2035/, clock);
    assert.ok(clock.includes(`until ${year + 15}`) && /short\./.test(clock), clock);
    await page.locator("#hv-keep").fill("2");
    clock = await page.locator("#hv-say").innerText();
    assert.match(clock, /to spare/, "the clock did not answer the shelf-life dial: " + clock);
    await page.locator("#hv-q").fill("2045");
    assert.match(await page.locator("#hv-say").innerText(), /around 2045/, "the clock did not answer the quantum dial");
    await page.locator("#hv-q").dispatchEvent("change");
    assert.ok(page.url().includes("keep=2") && page.url().includes("qday=2045"), "the dials are not kept in the URL");
    await page.locator("#tp-list").waitFor({ timeout: 15000 });
    assert.match(await page.locator("#tp-say").innerText(), /payment provider isn't \(js\.stripe\.com\)/);
    assert.match(await page.locator("#tp-list tbody tr").first().innerText(), /js\.stripe\.com/);
    await page.locator('#i-dial button[data-d="plain"]').click();
    await page.locator("#hv-say").waitFor();
    assert.ok(!(await page.locator("#hv-sw").count()), "the plain dial shows the expert migration control");

    // Watch mode on the domain page. CI's server needs no sign-in, so this browser has a workspace:
    // the answer comes first, the quiet claim line is there, and watching and claiming work.
    const domainRe = new RegExp(SMOKE_DOMAIN.replace(/\./g, "\\."));
    await page.locator("#w-panel #w-say").waitFor({ timeout: 15000 });
    assert.match(await page.locator("#w-claim-line").innerText(), /Is this your domain\? Claim it to get alerts when this changes\./);
    if (await page.locator("#w-stop").count()) { await page.locator("#w-stop").click(); await page.locator("#w-start").waitFor({ timeout: 15000 }); }
    await page.locator("#w-start").click();
    await page.locator("#w-stop").waitFor({ timeout: 15000 });
    assert.match(await page.locator("#w-say").innerText(), /^You're watching /);
    await page.locator("#w-claim-go").click();
    await page.locator("#w-rec-name").waitFor({ timeout: 15000 });
    assert.equal(await page.locator("#w-rec-name").innerText(), `_morrow-verify.${SMOKE_DOMAIN}`);
    assert.match(await page.locator("#w-rec-value").innerText(), /^morrow-verify=/);

    // What changed, what you watch, where alerts go. Push is off without VAPID keys and says so.
    await page.goto(`${base}/watching`, { waitUntil: "networkidle" });
    await page.locator("#wv-list").waitFor({ timeout: 15000 });
    assert.match(await page.locator("#wv-list").innerText(), domainRe);
    assert.match(await page.locator("#say").innerText(), /Nothing has changed|watched/);
    assert.ok((await page.locator("#wv-push").innerText()).length > 10, "the push line is empty");
    await page.locator("#wv-feed-new").click();
    await page.locator("#wv-feed-url").waitFor({ timeout: 15000 });
    assert.match(await page.locator("#wv-feed-url").innerText(), /\/api\/public\/watch-feed\/[A-Za-z0-9_-]{40,}\.atom$/);

    // The scanner names itself, and this page says what it sends and how to stop it.
    await page.goto(`${base}/about-scanner?host=${SMOKE_DOMAIN}`, { waitUntil: "networkidle" });
    await page.locator("#as-ua").waitFor({ timeout: 15000 });
    assert.equal(await page.locator("#as-ua").innerText(), "MorrowPQCheck/1.0 (+https://morrow.soqlab.com/about-scanner)");
    assert.match(await page.locator("#say").innerText(), /MorrowPQCheck/);
    assert.equal(await page.locator("#as-optout").getAttribute("href"), "/abuse");

    // Vendor check: the button answers as the list is typed; a report answers first, worst first,
    // with a note the buyer sends themselves.
    await page.goto(`${base}/vendors`, { waitUntil: "networkidle" });
    await page.fill("#vc-text", "Vendor,Site\nPayroll,https://payroll.example/login\nCRM,crm.example\nDup,crm.example\nops@x.example");
    assert.equal(await page.locator("#vc-go").innerText(), "Check 2 vendors");
    assert.match(await page.locator("#vc-count").innerText(), /1 duplicate removed, 1 skipped/);
    await routeReports(page);
    await page.goto(`${base}/vendors/r/${SMOKE_TOKEN}`, { waitUntil: "networkidle" });
    await page.locator("#vr-list").waitFor({ timeout: 15000 });
    assert.match(await page.locator("#say").innerText(), /^1 of your 2 checked vendors would let today's traffic be read later\. Worst: payroll\.example/);
    assert.match(await page.locator("#vr-list tbody tr").first().innerText(), /payroll\.example/);
    await page.locator("#vr-list [data-note]").first().click();
    assert.match(await page.locator("#vn-0").innerText(), /https:\/\/morrow\.example\/payroll\.example/);

    // What changed and a sector report, their APIs answered here.
    await page.goto(`${base}/changes`, { waitUntil: "networkidle" });
    await page.locator(".cg-list li").first().waitFor({ timeout: 15000 });
    assert.match(await page.locator("#say").innerText(), /3 sites became post-quantum ready and 0 dropped below B/);
    assert.equal(await page.locator(".cg-list li a").first().getAttribute("href"), "/acme.example");
    await page.goto(`${base}/report/finance`, { waitUntil: "networkidle" });
    await page.locator("svg.tl polyline").waitFor({ timeout: 15000 });
    assert.match(await page.locator("#say").innerText(), /up from 21\.3% in August 2026/);
    assert.match(await page.locator("#rp-cite").innerText(), /\/report\/finance$/);

    await page.goto(`${base}/wp-login.php`);
    assert.equal(await page.locator("#home-q").count(), 0, "a file path was treated as a domain");

    const phone = await browser.newContext({ viewport: { width: 360, height: 780 } });
    const small = await phone.newPage();
    small.on("pageerror", (e) => errors.push(String(e)));
    await routeDomain(small);
    await routeReports(small);
    for (const path of ["/", "/league", "/algorithms", "/trust", "/atlas", "/watching", "/about-scanner", `/${SMOKE_DOMAIN}?depth=expert`,
      "/vendors", `/vendors/r/${SMOKE_TOKEN}?depth=expert`, "/changes", "/report/finance?depth=expert"]) {
      await small.goto(`${base}${path}`, { waitUntil: "networkidle" });
      const wide = await small.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
      assert.ok(wide <= 1, `${path} overflows a 360px screen by ${wide}px`);
    }

    const noJs = await browser.newContext({ javaScriptEnabled: false });
    const plainPage = await noJs.newPage();
    const response = await plainPage.goto(`${base}/plain`);
    assert.equal(response.status(), 200);
    assert.ok((await plainPage.content()).includes("Domain to check"), "/plain does not work without JavaScript");
    const plainReport = await plainPage.goto(`${base}/plain/report`);
    assert.equal(plainReport.status(), 200);
    assert.ok((await plainPage.content()).includes("Sector reports"), "/plain/report does not work without JavaScript");
    assert.match(response.headers()["content-security-policy"] || "", /script-src 'none'/);

    assert.deepEqual(foreign, [], "the instrument contacted another origin");
    assert.deepEqual(errors, [], "JavaScript errors");
    console.log("PASS: no ambient motion, this origin only, recognizer, command bar, dial in the URL, harvest clock dials, outside services worst first, vendor check and its report, what changed, a sector report, watch and claim, /watching, /about-scanner, trust readout, plain without JS, 360px layout.");
  } finally {
    await browser.close();
  }
}

main().catch((error) => { console.error(error); process.exit(1); });
