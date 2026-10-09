const { chromium } = require("../.tools/video/node_modules/playwright");

const baseUrl = (process.env.PQC_E2E_BASE_URL || "http://localhost:8000").replace(/\/+$/, "");
const platformKey = process.env.PQC_E2E_PLATFORM_KEY || process.env.PQC_PLATFORM_ADMIN_KEY || "";
const artifactsDir = process.env.PQC_E2E_ARTIFACTS_DIR || "reports/e2e-smoke";
const e2eOrgId = process.env.PQC_E2E_ORG_ID || `e2e-smoke-${Date.now()}`;
// Overall budget. The console has 19 views and the overview alone fans out to ~14 endpoints, so the
// old 90s ceiling could not cover a full pass even when everything worked.
const timeoutMs = Number(process.env.PQC_E2E_TIMEOUT_MS || 600000);
// Per-view budget. A cold server answers its first requests in seconds; too tight a per-view timeout
// reports a slow start as a broken view.
const viewTimeoutMs = Number(process.env.PQC_E2E_VIEW_TIMEOUT_MS || 60000);
const stagePauseMs = Number(process.env.PQC_E2E_STAGE_PAUSE_MS || 0);
let currentStage = "startup";

function log(stage) {
  currentStage = stage;
  console.log(`[e2e] ${stage}`);
}

async function withTimeout(promise, ms, describe) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        // describe() is called when the timer fires, not when withTimeout is invoked. Passing a
        // pre-built string interpolated currentStage before main() had run, so every timeout was
        // reported as stage 'startup' regardless of where it actually hung -- which is exactly the
        // information needed to debug a timeout.
        timer = setTimeout(() => reject(new Error(`${describe()} timed out after ${ms}ms`)), ms);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function launchBrowser() {
  const args = ["--disable-gpu", "--disable-dev-shm-usage", "--no-sandbox"];
  try {
    return await chromium.launch({ headless: true, args });
  } catch (error) {
    return await chromium.launch({ headless: true, channel: "chrome", args });
  }
}

async function assertContains(page, path, labels) {
  await page.goto(`${baseUrl}${path}`, { waitUntil: "domcontentloaded", timeout: 30000 });
  await page.locator("body").waitFor({ timeout: 10000 });
  const text = await page.content();
  for (const label of labels) {
    if (!text.includes(label)) {
      throw new Error(`${path} did not contain expected text: ${label}`);
    }
  }
}

async function assertVisibleText(page, selector, expected, label = selector) {
  const text = await page.locator(selector).innerText({ timeout: 10000 });
  if (!text.includes(expected)) {
    throw new Error(`${label} did not contain expected text: ${expected}`);
  }
}

// Every view in the console's navigation, with the heading each one must render. Kept in step with
// the NAV array in backend/static/index.html -- a view added there without being added here is not
// covered, and one renamed there fails this test loudly rather than silently going untested.
const CONSOLE_VIEWS = [
  ["overview", "Overview"],
  ["scans", "TLS Scanner"],
  ["assets", "Asset Inventory"],
  ["cbom", "CBOM / SBOM"],
  ["hndl", "HNDL Exposure"],
  ["qday", "Q-Day Forecast"],
  ["graph", "Blast Radius"],
  ["canaries", "Canaries & QTISN"],
  ["g-airlock", "Airlock Guide"],
  ["g-trust-passport", "Passport Guide"],
  // The Administrator Guide is operator-only: it is hidden unless the server accepts this tab's
  // platform key, and this browser session carries none.
  ["airlock", "Quantum Airlock"],
  ["gateway", "Website Gateway"],
  ["remediation", "Remediation"],
  ["scanners", "Deep Scanners"],
  ["operations", "Operations"],
  ["governance", "Governance"],
  ["board", "Board & ROI"],
  ["vendors", "Third Party"],
  ["integrations", "Integrations"],
  ["knowledge", "Knowledge"],
  ["admin", "Administration"],
  ["api", "API Explorer"],
  ["guide", "Guide & Tutorial"],
];

// go() catches a render failure and substitutes this card, so a broken view still returns HTTP 200
// with a plausible-looking page. Checking the heading alone would pass; this is what actually
// distinguishes a rendered view from a failed one.
const RENDER_FAILURE_MARKER = "View failed to render";

// A rendered view always carries headings, labels and figures well past this; the skeleton state
// carries none. Low enough not to encode any view's specific content, high enough that a blank or
// half-built body cannot pass.
const MIN_VIEW_TEXT = 40;

async function testMainUi(page) {
  log("console loads");
  await page.goto(`${baseUrl}/ui/`, { waitUntil: "domcontentloaded", timeout: 30000 });
  await page.locator("#app").waitFor({ timeout: 15000 });
  await page.locator("#nav .nav[data-go]").first().waitFor({ timeout: 15000 });

  // Every navigation button must route to a registered view. go() falls back to "overview" for an
  // unknown id, so a nav entry with no matching view is not an error the user ever sees — the button
  // simply lands them somewhere else. That is worse than a broken link, because nothing looks wrong.
  const orphans = await page.evaluate(() => {
    if (typeof VIEWS === "undefined") return null;
    return [...document.querySelectorAll("#nav .nav[data-go]")]
      .map(b => b.dataset.go)
      .filter(id => !(id in VIEWS));
  });
  if (orphans === null) {
    throw new Error("VIEWS is not reachable, so navigation integrity cannot be checked");
  }
  if (orphans.length) {
    throw new Error(
      `these navigation entries are not registered views, so clicking them silently lands on ` +
      `Overview: ${orphans.join(", ")}. Either register them in VIEWS or move them out of NAV ` +
      `(entries carrying a "body" field are GUIDE content, not views).`
    );
  }

  const navCount = await page.locator("#nav .nav[data-go]").count();
  if (navCount !== CONSOLE_VIEWS.length) {
    throw new Error(
      `navigation has ${navCount} entries, expected ${CONSOLE_VIEWS.length}. ` +
      `If a view was added or removed, update CONSOLE_VIEWS in this script.`
    );
  }

  for (const [id, heading] of CONSOLE_VIEWS) {
    log(`view: ${id}`);
    await page.locator(`.nav[data-go="${id}"]`).evaluate((el) => el.click());
    // go() replaces #view with a skeleton, then awaits the view's render. Waiting on the heading
    // first ensures the route switched before the body is inspected.
    await page.waitForFunction(
      (expected) => document.querySelector("#vTitle")?.textContent?.trim() === expected,
      heading,
      { timeout: viewTimeoutMs }
    );
    // go() fills #view with skeleton placeholders that carry no text, then awaits the view's render,
    // so accumulated text is what distinguishes "rendered" from "still loading". Absence of
    // skeletons is NOT the signal: several views deliberately leave placeholders inside cards for
    // panels loaded on demand behind a button ("Recommend", "Load progress"), and treating those as
    // unfinished flags a correct design as broken.
    await page.waitForFunction(
      (min) => {
        const host = document.querySelector("#view");
        return host && host.innerText.trim().length >= min;
      },
      MIN_VIEW_TEXT,
      { timeout: viewTimeoutMs }
    );
    const body = await page.locator("#view").innerText({ timeout: 10000 });
    if (body.includes(RENDER_FAILURE_MARKER)) {
      throw new Error(`view '${id}' rendered its failure card instead of content`);
    }
  }

  log("deep link restores a view");
  await page.goto(`${baseUrl}/ui/#governance`, { waitUntil: "domcontentloaded", timeout: 30000 });
  await page.waitForFunction(
    () => document.querySelector("#vTitle")?.textContent?.trim() === "Governance",
    undefined,
    { timeout: viewTimeoutMs }
  );

  log("guide has its tutorial sections");
  await page.locator('.nav[data-go="guide"]').evaluate((el) => el.click());
  await page.waitForFunction(
    () => document.querySelector("#vTitle")?.textContent?.trim() === "Guide & Tutorial",
    undefined,
    { timeout: viewTimeoutMs }
  );
  const guideSections = await page.locator("#view h3, #view h4").count();
  if (guideSections < 10) {
    throw new Error(`guide rendered only ${guideSections} section headings, expected at least 10`);
  }
}

async function testPublicPages(page) {
  log("public launch and legal pages");
  await assertContains(page, "/launch", [
    "Prove quantum readiness without deep customer access.",
    "Quantum Airlock",
  ]);
  await assertContains(page, "/security", ["minimum customer access", "Production Controls"]);
  await assertContains(page, "/privacy", ["Privacy Policy", "Data We Do Not Collect By Default"]);
  await assertContains(page, "/terms", ["Terms of Service", "Authorization To Scan"]);
  await assertContains(page, "/support", ["How to reach us", "Incident Process"]);
  await assertContains(page, "/enterprise-admin", ["Enterprise Control Center", "Traffic Lens"]);
}

async function testVendorAdmin(page) {
  log("vendor admin static UI loads");
  await assertContains(page, "/vendor-admin/", [
    "Platform Administration",
    "Telemetry",
    "Customer feedback",
    "Admin mode",
    "Feature Flags",
  ]);

  if (!platformKey) {
    console.log("Skipping vendor admin authenticated flow; set PQC_E2E_PLATFORM_KEY to enable it.");
    return;
  }

  log("vendor admin authenticated flow");
  await page.locator("#platformKey").fill(platformKey);
  await page.locator("#loadBtn").evaluate((el) => el.click(), { timeout: 10000 });
  await page.locator("#apiState").filter({ hasText: "API connected" }).waitFor({ timeout: 30000 });
  await assertVisibleText(page, "#adminModeBody", "Admin mode", "Admin mode box");
  // Grouped dropdown navigation: Security > Launch readiness, then Security > Security truth.
  await page.locator('.sh-top[data-top="security"]').click();
  await page.locator('.sh-link[data-route="launch"]').click();
  await assertVisibleText(page, "#readinessBody", "Production", "Readiness panel");
  await page.locator('.sh-top[data-top="security"]').click();
  await page.locator('.sh-link[data-route="security-truth"]').click();
  await assertVisibleText(page, "#securityTruthBody", "open high/critical", "Security Truth panel");
}

async function testTrafficMonitor(page) {
  log("traffic monitor static UI loads");
  await assertContains(page, "/vendor-admin/traffic.html", [
    "Traffic Monitor",
    "No payload capture",
    "No-Login Boundary",
  ]);

  if (!platformKey) {
    console.log("Skipping traffic monitor authenticated flow; set PQC_E2E_PLATFORM_KEY to enable it.");
    return;
  }

  log("traffic monitor authenticated flow");
  await page.locator("#platformKey").fill(platformKey);
  await page.locator("#platformRole").selectOption("owner");
  await page.locator("#refreshBtn").evaluate((el) => el.click(), { timeout: 10000 });
  await page.locator("#apiState").filter({ hasText: "Connected" }).waitFor({ timeout: 30000 });
  await assertVisibleText(page, "#proxyState", "proxy", "Proxy state");

  const ndjson = await page.request.get(`${baseUrl}/platform/traffic/export.ndjson`, {
    headers: { "x-platform-key": platformKey, "x-platform-admin-role": "auditor", "x-org-id": e2eOrgId },
  });
  if (!ndjson.ok()) throw new Error(`/platform/traffic/export.ndjson returned ${ndjson.status()}`);

  const otel = await page.request.get(`${baseUrl}/platform/traffic/otel`, {
    headers: { "x-platform-key": platformKey, "x-platform-admin-role": "auditor", "x-org-id": e2eOrgId },
  });
  if (!otel.ok()) throw new Error(`/platform/traffic/otel returned ${otel.status()}`);
  const body = await otel.json();
  if (!body.resourceLogs) throw new Error("traffic OTEL export did not include resourceLogs");
}

async function main() {
  const fs = require("fs");
  fs.mkdirSync(artifactsDir, { recursive: true });
  // Clear any failure report from an earlier run. It is written to a fixed filename, so without
  // this a stale failure.json outlives the problem it described and reads as a currently-failing
  // smoke test long after the run has started passing.
  try {
    fs.rmSync(`${artifactsDir}/failure.json`, { force: true });
  } catch {}
  let browser;
  let context;
  try {
    browser = await launchBrowser();
    context = await browser.newContext({
      viewport: { width: 1440, height: 1100 },
      reducedMotion: "reduce",
      extraHTTPHeaders: { "x-org-id": e2eOrgId },
    });
    const page = await context.newPage();
    page.setDefaultTimeout(15000);
    page.setDefaultNavigationTimeout(30000);

    page.on("pageerror", (error) => console.error(`[browser pageerror] ${error.message || error}`));
    page.on("console", (msg) => {
      if (["error", "warning"].includes(msg.type())) {
        console.error(`[browser ${msg.type()}] ${msg.text()}`);
      }
    });

    log("health check");
    const health = await page.request.get(`${baseUrl}/health`);
    if (!health.ok()) throw new Error(`/health returned ${health.status()}`);

    await testPublicPages(page);
    await testMainUi(page);
    // The console pass alone can use most of the per-IP request budget (PQC_RATE_LIMIT_MAX_REQUESTS
    // per window). Set PQC_E2E_STAGE_PAUSE_MS to about one window when the smoke shares the default limit.
    await page.waitForTimeout(stagePauseMs);
    await testVendorAdmin(page);
    await page.waitForTimeout(stagePauseMs);
    await testTrafficMonitor(page);

    console.log(`E2E smoke passed against ${baseUrl}`);
  } finally {
    if (context) {
      await context.close().catch(() => {});
    }
    if (browser) {
      await browser.close().catch(() => {});
    }
  }
}

withTimeout(main(), timeoutMs, () => `E2E smoke at stage '${currentStage}'`).catch(async (error) => {
  try {
    const fs = require("fs");
    fs.mkdirSync(artifactsDir, { recursive: true });
    fs.writeFileSync(`${artifactsDir}/failure.json`, JSON.stringify({
      baseUrl,
      stage: currentStage,
      error: String(error && error.stack || error),
      generated_at: new Date().toISOString(),
    }, null, 2));
  } catch {}
  console.error(error.message || error);
  process.exit(1);
});
