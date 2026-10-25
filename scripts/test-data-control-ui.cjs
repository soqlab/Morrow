/* Real isolated backend + browser. No production database, model traffic or deployment credentials. */
const { spawn } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const net = require("node:net");
const crypto = require("node:crypto");
const assert = require("node:assert/strict");
const root = path.resolve(__dirname, "..");
let playwright;
try { playwright = require("playwright"); }
catch { playwright = require(path.join(root, ".tools/video/node_modules/playwright")); }

(async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "pq-ai-ui-"));
  const port = await new Promise(resolve => {
    const socket = net.createServer(); socket.listen(0, "127.0.0.1", () => {
      const port = socket.address().port; socket.close(() => resolve(port));
    });
  });
  const base = `http://127.0.0.1:${port}`;
  const python = process.env.MORROW_TEST_PYTHON || path.join(root, "backend/.venv", process.platform === "win32" ? "Scripts/python.exe" : "bin/python");
  const testEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) =>
    !/^(MORROW_|OPENAI_|ANTHROPIC_|CELERY_|SENTRY_|OTEL_|GITHUB_)/i.test(key)));
  const server = spawn(python, ["-c", `import app,uvicorn
def no_model(*a,**kw): raise RuntimeError("Model I/O forbidden during UI checks")
app._ai_privacy.openai_completion=no_model
app.limiter.enabled=False
uvicorn.run(app.app,host="127.0.0.1",port=${port},log_level="error")`], {
    cwd:path.join(root,"backend"), windowsHide:true, stdio:["ignore","pipe","pipe"],
    env:{...testEnv, PYTHON_DOTENV_DISABLED:"1", WORKER_ROLE:"api", REDIS_URL:"", CELERY_BROKER_URL:"", CELERY_RESULT_BACKEND:"",
      MORROW_SCANNER_DB:path.join(directory,"ui.db"), MORROW_MAIN_DB_BACKEND:"sqlite", MORROW_FEATURE_STORE_BACKEND:"sqlite",
      DATABASE_URL:"", MORROW_PRODUCT_DATABASE_URL:"", MORROW_ENVIRONMENT:"local", MORROW_AUTH_MODE:"headers", MORROW_AUTH_REQUIRED:"0", MORROW_DEFAULT_ROLE:"admin",
      MORROW_AUTH_JWT_SECRET:crypto.randomBytes(40).toString("hex"), MORROW_ADMIN_PASSWORD:"", MORROW_API_KEY:"", MORROW_BILLING_ENFORCE:"0",
      MORROW_VAULT_MASTER_KEY:crypto.randomBytes(32).toString("base64url")+"=", OPENAI_API_KEY:"ui-test-not-real", ANTHROPIC_API_KEY:"", MORROW_AI_LOCAL_URL:"",
      MORROW_RATE_LIMIT_MAX_REQUESTS:"100000", MORROW_RATE_LIMIT_DEFAULT:"100000/minute"}
  });
  let logs="", browser, spawnError;
  server.on("error",error => { spawnError=error; });
  server.stdout.on("data",chunk => { logs=(logs+chunk).slice(-20000); });
  server.stderr.on("data",chunk => { logs=(logs+chunk).slice(-20000); });
  try {
    const deadline=Date.now()+180000;
    for(;;) {
      if(spawnError) throw spawnError;
      if(server.exitCode!==null) throw new Error(`Isolated backend exited (${server.exitCode}): ${logs}`);
      try { if((await fetch(base+"/health",{signal:AbortSignal.timeout(2000)})).ok) break; } catch {}
      if(Date.now()>=deadline) throw new Error("Isolated backend startup timeout: "+logs);
      await new Promise(resolve=>setTimeout(resolve,500));
    }
    const channel=process.env.MORROW_TEST_BROWSER_CHANNEL || (process.platform === "win32" ? "msedge" : undefined);
    browser=await playwright.chromium.launch({headless:true,channel});
    const context=await browser.newContext({viewport:{width:1440,height:1100},reducedMotion:"reduce"});
    await context.addInitScript(()=>{
      localStorage.setItem("morrow_role","admin"); localStorage.setItem("pq_actor","ui-test-admin");
      localStorage.setItem("morrow_theme","light");
    });
    await context.route("**/*", route=>new URL(route.request().url()).origin===base ? route.continue() : route.abort());
    const page=await context.newPage(), errors=[];
    page.on("pageerror",error=>errors.push(error.message));
    await page.goto(base+"/ui/#data-control");
    await page.locator("#dcPolicy").waitFor({timeout:30000});
    assert.match(await page.locator(".dc-boundary").innerText(),/AI off/);
    await page.locator('#dcPolicy [name="mode"]').selectOption("approved_external");
    await page.locator('#dcPolicy [value="metadata_analysis"]').check();
    await page.getByRole("button",{name:"Review exact policy",exact:true}).click();
    await page.getByRole("button",{name:"Approve this exact policy",exact:true}).click();
    await page.waitForFunction(()=>document.querySelector(".dc-boundary")?.textContent.includes("Policy v1"));
    await page.locator('#dcPreview [name="metadata"]').fill('{"algorithm":"RSA","key_bits":2048,"hostname":"private.internal"}');
    await page.getByRole("button",{name:"Preview model payload",exact:true}).click();
    await page.locator("#dcPreviewResult:not([hidden])").waitFor();
    const preview=JSON.parse(await page.locator("#dcPreviewResult").innerText());
    assert.equal(preview.sent,false); assert(!JSON.stringify(preview).includes("private.internal"));
    const downloaded=page.waitForEvent("download");
    await page.getByRole("button",{name:"Download local filtering kit",exact:true}).click();
    const kit=await downloaded; assert.equal(kit.suggestedFilename(),"customer-data-control.zip");
    assert.equal(await kit.failure(),null);
    await page.getByRole("button",{name:"Stop AI now",exact:true}).click();
    await page.waitForFunction(()=>document.querySelector(".dc-boundary")?.textContent.includes("AI off"));
    await page.screenshot({path:path.join(directory,"data-control-desktop.png"),fullPage:true});
    await page.setViewportSize({width:390,height:844});
    await page.screenshot({path:path.join(directory,"data-control-mobile.png"),fullPage:true});
    assert(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth+1),"Mobile page overflows");
    await page.goto(base+"/ui/ai-trust.html");
    assert.match(await page.locator("h1").innerText(),/Your data is not/);
    assert(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth+1),"Public page overflows");
    const viewer=await browser.newContext({viewport:{width:1280,height:800}});
    await viewer.addInitScript(()=>localStorage.setItem("morrow_role","viewer"));
    const reader=await viewer.newPage(); await reader.goto(base+"/ui/#data-control");
    await reader.locator("#dcPolicy").waitFor();
    assert(await reader.getByRole("button",{name:"Stop AI now",exact:true}).isDisabled());
    assert(await reader.getByRole("button",{name:"Review exact policy",exact:true}).isDisabled());
    assert.deepEqual(errors,[]);
    console.log(JSON.stringify({passed:true,checks:["desktop","mobile","policy review/approval","payload preview","kit download","stop","viewer controls","public trust page"],artifacts:directory}));
  } finally {
    if(browser) await browser.close();
    // The child is this test's isolated server, never the user's running platform.
    if(server.pid && server.exitCode===null) {
      if(process.platform==="win32") {
        await new Promise(resolve=>spawn("taskkill",["/PID",String(server.pid),"/T","/F"],{windowsHide:true,stdio:"ignore"}).on("exit",resolve));
      } else server.kill("SIGTERM");
    }
  }
})().catch(error=>{console.error(error);process.exitCode=1;});
