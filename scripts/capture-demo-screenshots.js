const fs = require("fs");
const path = require("path");
const { chromium } = require("playwright");

const repoRoot = path.resolve(__dirname, "..");
const outDir = path.join(repoRoot, "demo", "video", "screens");
const baseUrl = process.env.MORROW_DEMO_BASE_URL || "http://localhost:8000";

fs.mkdirSync(outDir, { recursive: true });

async function safeClick(page, selector, timeout = 5000) {
  try {
    const locator = page.locator(selector).first();
    await locator.waitFor({ state: "visible", timeout });
    await locator.click({ timeout });
    return true;
  } catch {
    return false;
  }
}

async function scrollTo(page, selector) {
  await page.evaluate((sel) => {
    const el = document.querySelector(sel);
    if (el) el.scrollIntoView({ block: "center", inline: "nearest" });
  }, selector);
  await page.waitForTimeout(900);
}

async function shot(page, name, selector = null) {
  if (selector) await scrollTo(page, selector);
  await page.screenshot({
    path: path.join(outDir, `${name}.png`),
    fullPage: false,
  });
}

async function main() {
  const browser = await chromium.launch({
    channel: "msedge",
    headless: true,
  });

  const demoRole = process.env.MORROW_DEMO_USER_ROLE || "admin";
  const demoUserId = process.env.MORROW_DEMO_USER_ID || "demo-video";
  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    deviceScaleFactor: 1,
    extraHTTPHeaders: {
      "x-user-role": demoRole,
      "x-user-id": demoUserId,
    },
  });

  const page = await context.newPage();
  page.setDefaultTimeout(12000);

  await page.goto(`${baseUrl}/ui/`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(2500);

  await shot(page, "01-dashboard-hero");

  await safeClick(page, "#operatorRefreshBtn", 3000);
  await safeClick(page, "#dash_refresh", 3000);
  await page.waitForTimeout(2500);

  await shot(page, "02-board-risk-radar", "#dash_board_risk");
  await shot(page, "03-readiness-checklist", "#dash_e2e_readiness");
  await shot(page, "04-compliance-summary", "#dash_org_summary");
  await shot(page, "05-crypto-weather", "#dash_crypto_weather");
  await shot(page, "06-flight-recorder", "#dash_flight_recorder");
  await shot(page, "07-enterprise-metrics", "#dash_enterprise_metrics");

  await safeClick(page, "#runtimeTrafficBtn");
  await page.waitForTimeout(900);
  await safeClick(page, "#rt_topology_btn", 3000);
  await page.waitForTimeout(1800);
  await shot(page, "08-runtime-topology", "#runtimeTrafficBackdrop");
  await safeClick(page, "#runtimeTrafficBackdrop .modalClose, #runtimeTrafficBackdrop button:has-text('Close')", 1000);
  await page.keyboard.press("Escape").catch(() => {});

  await shot(page, "09-workflow-status", "#operatorWorkflowBoard");
  await shot(page, "10-github-ownership", "#githubConnectPanelTitle");

  await safeClick(page, "#remediationQueueBtn");
  await page.waitForTimeout(2200);
  await shot(page, "11-remediation-queue", "#remediationQueueBackdrop");
  await page.keyboard.press("Escape").catch(() => {});

  const reportPage = await context.newPage();
  await reportPage.goto(`${baseUrl}/org/compliance-report?format=json`, { waitUntil: "domcontentloaded" });
  await reportPage.waitForTimeout(1200);
  await reportPage.screenshot({
    path: path.join(outDir, "12-evidence-report.png"),
    fullPage: false,
  });
  await reportPage.close();

  await page.goto(`${baseUrl}/ui/`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1200);
  await shot(page, "13-closing-dashboard");

  await browser.close();
  console.log(`Captured demo screenshots in ${outDir}`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
