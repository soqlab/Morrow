// Customer-run application tests: no browser credentials or payloads are sent to the control plane.
const fs = require("node:fs");
const { chromium } = require("../.tools/video/node_modules/playwright");

async function run(manifest, approved) {
  if (!approved) throw new Error("Explicit --approved is required. Use staging and test accounts; these tests can submit forms.");
  const base = new URL(manifest.base_url);
  if (!["https:", "http:"].includes(base.protocol) || base.username || base.password) throw new Error("Invalid approved base URL");
  if (base.protocol !== "https:" && !["127.0.0.1", "localhost"].includes(base.hostname)) throw new Error("Non-local tests require HTTPS");
  const allowed = new Set([base.origin, ...(manifest.allowed_origins || [])]);
  const kinds = new Set(["login", "forms", "uploads", "websocket"]);
  if (!Array.isArray(manifest.tests) || manifest.tests.length !== 4 || new Set(manifest.tests.map(t => t.kind)).size !== 4 || manifest.tests.some(t => !kinds.has(t.kind))) throw new Error("Specify each of the four application journeys once");
  let browser;
  try { browser = await chromium.launch({ headless: true }); }
  catch { browser = await chromium.launch({ headless: true, channel: "chrome" }); }
  const report = { source: "customer-run-playwright", host: base.hostname, checked_at: new Date().toISOString(), tests: [] };
  const target = path => { const url = new URL(path, base); if (url.origin !== base.origin) throw new Error("Test action left the approved application origin"); return url.href; };
  try {
    for (const test of manifest.tests) {
      if (test.not_applicable) {
        if (String(test.not_applicable).length < 8) throw new Error("Explain non-applicability");
        report.tests.push({ kind: test.kind, result: "not_applicable", basis: "customer declaration", evidence: test.not_applicable });
        continue;
      }
      const context = await browser.newContext({ serviceWorkers: "block" });
      await context.route("**/*", route => allowed.has(new URL(route.request().url()).origin) ? route.continue() : route.abort());
      await context.routeWebSocket(/.*/, socket => {
        const endpoint = new URL(socket.url());
        endpoint.protocol = endpoint.protocol === "wss:" ? "https:" : "http:";
        if (allowed.has(endpoint.origin)) socket.connectToServer();
        else socket.close({ code: 1008, reason: "Unapproved test origin" });
      });
      const page = await context.newPage(); page.setDefaultTimeout(10000);
      let index = 0;
      const started = Date.now();
      try {
        if (!test.steps?.length) throw new Error("No test steps provided");
        for (const step of test.steps) {
          index++;
          if (step.action === "visit") await page.goto(target(step.path));
          else if (step.action === "fill") {
            const value = step.value_env ? process.env[step.value_env] : step.value;
            if (value == null) throw new Error("Test input not configured");
            await page.locator(step.selector).fill(value);
          } else if (step.action === "click") await page.locator(step.selector).click();
          else if (step.action === "expect_text") {
            await page.getByText(step.text, { exact: Boolean(step.exact) }).first().waitFor();
          } else if (step.action === "expect_path") await page.waitForURL(target(step.path));
          else if (step.action === "upload") {
            if (!step.file_env || !process.env[step.file_env]) throw new Error("Approved fixture file is required");
            await page.locator(step.selector).setInputFiles(process.env[step.file_env]);
          } else if (step.action === "websocket") {
            const endpoint = new URL(target(step.path)); endpoint.protocol = endpoint.protocol === "https:" ? "wss:" : "ws:";
            await page.evaluate(({ url, send, expect }) => new Promise((resolve, reject) => {
              const ws = new WebSocket(url);
              const timer = setTimeout(() => { ws.close(); reject(new Error("WebSocket test timeout")); }, 8000);
              ws.onopen = () => ws.send(send);
              ws.onmessage = event => { clearTimeout(timer); ws.close(); event.data === expect ? resolve() : reject(new Error("Unexpected test response")); };
              ws.onerror = () => { clearTimeout(timer); ws.close(); reject(new Error("WebSocket failed")); };
            }), { url: endpoint.href, send: step.send, expect: step.expect });
          } else throw new Error("Unsupported test action");
        }
        report.tests.push({ kind: test.kind, result: "passed", duration_ms: Date.now() - started });
      } catch {
        // Playwright errors can include entered credentials or page text. Do not include them in the report.
        report.tests.push({ kind: test.kind, result: "failed", step: index, duration_ms: Date.now() - started, error: "Application assertion failed; inspect in the customer environment." });
      } finally { await context.close(); }
    }
  } finally { await browser.close(); }
  report.passed = report.tests.every(test => test.result !== "failed");
  return report;
}

if (require.main === module) {
  const [manifestPath, reportPath] = process.argv.slice(2);
  if (!manifestPath || !reportPath || reportPath.startsWith("--")) {
    console.error("Usage: node scripts/gateway-journeys.js MANIFEST.json REPORT.json --approved"); process.exitCode = 2;
  } else {
    Promise.resolve().then(() => run(JSON.parse(fs.readFileSync(manifestPath, "utf8")), process.argv.includes("--approved")))
      .then(report => { fs.writeFileSync(reportPath, JSON.stringify(report, null, 2)); console.log(report.passed ? "Application checks passed; review the local report." : "Application checks failed; do not activate blocking."); process.exitCode = report.passed ? 0 : 1; })
      .catch(() => { console.error("Runner could not start. Check approval, manifest, fixture inputs, and browser installation. No readiness result was issued."); process.exitCode = 2; });
  }
}
module.exports = { run };
