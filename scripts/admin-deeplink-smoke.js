// Operator console deep-link smoke: every record route GET /platform/notifications and
// GET /platform/search can emit (#/feedback?id=…, #/api-keys?id=…, #/announcements?id=…,
// #/autopatch?id=…, #/users?q=…, #/support-sessions?id|org=…, #/customers/<org>, #/jobs?id=…,
// #/alert-routing?id=…, and the #/readiness and #/logins aliases)
// opens its page, selects the record, gives it focus, opens its detail where there is one, and
// clears the query from the address. A record that no longer exists gets the "This item no longer
// exists" note instead. Records this smoke needs are created through the API and removed again.
const { chromium } = require("../.tools/video/node_modules/playwright");
const assert = require("node:assert/strict");
const base = (process.env.MORROW_E2E_BASE_URL || "http://127.0.0.1:8001").replace(/\/$/, "");
const key = process.env.MORROW_E2E_PLATFORM_KEY;
if (!key) throw new Error("MORROW_E2E_PLATFORM_KEY is required for the deep-link smoke.");

const HEADERS = { "x-platform-key": key, "x-platform-admin-role": "owner" };
const hashOf = page => page.evaluate(() => location.hash);
const selected = page => page.evaluate(() => {
  const el = document.querySelector("[data-deep-link-selected]");
  if (!el) return null;
  return {
    id: el.dataset.recordId || "", email: el.dataset.recordEmail || "", org: el.dataset.recordOrg || "",
    focused: document.activeElement === el, highlighted: el.classList.contains("deepLinkHit"),
    page: el.closest("[data-page]")?.dataset.page || "", visible: !el.closest("[data-page]")?.hidden,
    detailOpen: !!el.querySelector("details[open]"), text: el.innerText.slice(0, 80),
  };
});
const note = page => page.evaluate(() => {
  const el = document.querySelector(".deepLinkNote");
  return el ? { text: el.innerText, focused: document.activeElement === el, page: el.closest("[data-page]")?.dataset.page || "" } : null;
});

async function open(page, hash, pageKey) {
  // Start from a clean board: the console clears the last selection when the route changes.
  await page.evaluate(() => { location.hash = "#/dashboard"; });
  await page.waitForFunction(() => !document.querySelector("[data-deep-link-selected], .deepLinkNote"), null, { timeout: 15000 });
  await page.waitForTimeout(300);
  await page.evaluate(h => { location.hash = h; }, hash);
  await page.waitForFunction(key => !!document.querySelector(`[data-page="${key}"] [data-deep-link-selected], [data-page="${key}"] .deepLinkNote, [data-page="${key}"] #c360Notice .notice`), pageKey, { timeout: 45000 })
    .catch(() => {});
}

async function main() {
  const api = async (method, path, body) => {
    const res = await fetch(base + path, {
      method, headers: body ? { ...HEADERS, "Content-Type": "application/json" } : HEADERS,
      body: body ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    let data = {};
    try { data = text ? JSON.parse(text) : {}; } catch { data = { detail: text }; }
    return { ok: res.ok, status: res.status, data };
  };

  // ---------- records to link to ----------
  const cleanup = [];
  const orgs = await api("GET", "/platform/customers");
  const org = (orgs.data.customers || [])[0]?.organization_id;
  assert.ok(org, "at least one organization is needed");

  let feedback = (await api("GET", "/platform/feedback?limit=1")).data.items?.[0];
  if (!feedback) {
    const made = await api("POST", "/feedback", { message: "Deep-link smoke item.", category: "other", rating: 5 });
    assert.equal(made.ok, true, `creating a feedback item: ${JSON.stringify(made.data)}`);
    feedback = made.data.feedback || made.data;
    cleanup.push(["feedback", () => api("PATCH", `/platform/feedback/${feedback.id}`, { status: "declined", admin_note: "deep-link smoke" })]);
  }

  // A long message, so the console folds it into a details block the deep link has to open.
  const longMessage = "Deep-link smoke: " + "this message is long enough that the console folds it away. ".repeat(6);
  const madeLong = await api("POST", "/feedback", { message: longMessage, category: "idea", rating: 4 });
  const longFeedback = madeLong.ok ? (madeLong.data.feedback || madeLong.data) : null;
  if (longFeedback) cleanup.push(["long feedback", () => api("PATCH", `/platform/feedback/${longFeedback.id}`, { status: "declined", admin_note: "deep-link smoke" })]);
  else console.log(`Long feedback item not created (${madeLong.status}); the single-item deep link is skipped.`);

  // GET /platform/feedback/{id} is what lets the console tell "older than the page we loaded" apart
  // from "deleted". Check the route itself before asking the browser to rely on it.
  {
    const listed = (await api("GET", "/platform/feedback?limit=1")).data.items?.[0];
    const single = await api("GET", `/platform/feedback/${listed.id}`);
    assert.equal(single.ok, true, `reading one feedback item: ${JSON.stringify(single.data)}`);
    assert.deepEqual(Object.keys(single.data.feedback).sort(), Object.keys(listed).sort(),
      "the single read returns the same shape as the list entry");
    assert.equal(single.data.feedback.message, listed.message, "the full message text comes back");
    const absent = await api("GET", "/platform/feedback/999999901");
    assert.equal(absent.status, 404, "a feedback item that does not exist is a real 404");
    console.log("GET /platform/feedback/{id}: same shape as the list, 404 when gone.");
  }

  const ann = await api("POST", "/platform/announcements", {
    title: "Deep-link smoke", body: "Created by scripts/admin-deeplink-smoke.js.", severity: "info", audience: "all", organization_ids: [],
  });
  assert.equal(ann.ok, true, `creating an announcement: ${JSON.stringify(ann.data)}`);
  const announcement = ann.data.announcement || ann.data;
  cleanup.push(["announcement", () => api("DELETE", `/platform/announcements/${announcement.id}?reason=deep-link%20smoke%20cleanup`)]);

  const madeKey = await api("POST", `/platform/customers/${encodeURIComponent(org)}/api-keys`, {
    name: "deep-link smoke", scopes: ["read"], expires_in_days: 1, reason: "deep-link smoke check",
  });
  const apiKey = madeKey.ok ? madeKey.data.key : null;
  if (apiKey) cleanup.push(["api key", () => api("POST", `/platform/api-keys/${encodeURIComponent(apiKey.id)}/revoke`, { reason: "deep-link smoke cleanup" })]);
  else console.log(`API key not created (${madeKey.status}); using an existing key if there is one.`);
  const anyKey = apiKey || (await api("GET", "/platform/api-keys")).data.items?.[0];

  const autopatch = (await api("GET", "/platform/autopatches?limit=1")).data.items?.[0];
  const user = (await api("GET", "/platform/users?limit=5")).data.items?.find(u => u.email) || (await api("GET", "/platform/users?limit=1")).data.items?.[0];
  const job = (await api("GET", "/platform/jobs")).data.jobs?.[0];

  const madeSession = await api("POST", `/platform/customers/${encodeURIComponent(org)}/support-sessions`, {
    reason: "Deep-link smoke: checking notification deep links reach the session.", minutes: 5, ticket_ref: "smoke",
  });
  const session = madeSession.ok ? madeSession.data.session : null;
  if (session) cleanup.push(["support session", () => api("POST", `/platform/support-sessions/${encodeURIComponent(session.id)}/revoke`, { reason: "deep-link smoke cleanup" })]);
  else console.log(`Support session not created (${madeSession.status}); its deep link is checked for the missing case only.`);

  const madeChannel = await api("POST", "/platform/alert-channels", {
    name: "deep-link smoke", kind: "generic_webhook", target: "https://example.invalid/hook", enabled: false,
    min_severity: "critical", kinds: [], reason: "deep-link smoke check",
  });
  const channel = madeChannel.ok ? (madeChannel.data.channel || madeChannel.data.item || madeChannel.data) : null;
  if (channel?.id) cleanup.push(["alert channel", () => api("DELETE", `/platform/alert-channels/${encodeURIComponent(channel.id)}?reason=deep-link%20smoke%20cleanup`)]);
  else console.log(`Alert channel not created (${madeChannel.status}); its deep link is checked for the missing case only.`);

  let browser;
  try { browser = await chromium.launch({ headless: true }); }
  catch { browser = await chromium.launch({ headless: true, channel: "chrome" }); }
  let failures = 0;
  try {
    const context = await browser.newContext({ viewport: { width: 1440, height: 950 } });
    const page = await context.newPage();
    const errors = [];
    page.on("pageerror", error => errors.push(error.message));

    await page.goto(base + "/vendor-admin/");
    await page.locator("#platformKey").fill(key);
    await page.locator("#loadBtn").click();
    await page.waitForFunction(() => document.querySelector("#apiState").textContent === "API connected", null, { timeout: 60000 });
    console.log("Connected to the operator console.");

    const checks = [
      feedback && { what: "feedback", hash: `#/feedback?id=${feedback.id}`, page: "feedback", id: String(feedback.id) },
      anyKey && { what: "api key", hash: `#/api-keys?id=${encodeURIComponent(anyKey.id)}`, page: "api-keys", id: String(anyKey.id) },
      { what: "announcement", hash: `#/announcements?id=${announcement.id}`, page: "announcements", id: String(announcement.id) },
      autopatch && { what: "autopatch", hash: `#/autopatch?id=${autopatch.id}`, page: "autopatch", id: String(autopatch.id), detail: "#autopatchDetail" },
      user && { what: "user", hash: `#/users?q=${encodeURIComponent(user.email || user.user_id)}`, page: "users", id: String(user.user_id) },
      { what: "customer 360", hash: `#/customers/${encodeURIComponent(org)}`, page: "customer360" },
      job && { what: "job", hash: `#/jobs?id=${encodeURIComponent(job.key)}`, page: "jobs", id: String(job.key) },
      session && { what: "support session by id", hash: `#/support-sessions?id=${encodeURIComponent(session.id)}`, page: "support-sessions", id: String(session.id), detailOpen: true },
      session && { what: "support session by org", hash: `#/support-sessions?org=${encodeURIComponent(org)}`, page: "support-sessions", org },
      channel?.id && { what: "alert channel", hash: `#/alert-routing?id=${encodeURIComponent(channel.id)}`, page: "alert-routing", id: String(channel.id) },
      { what: "readiness alias", hash: "#/readiness", page: "launch" },
      { what: "failed-login alias", hash: "#/logins", page: "audit" },
    ].filter(Boolean);

    for (const check of checks) {
      await open(page, check.hash, check.page);
      const hit = await selected(page);
      try {
        assert.ok(hit, `${check.what}: a record is selected`);
        assert.equal(hit.page, check.page, `${check.what}: selection is on the ${check.page} page`);
        assert.equal(hit.visible, true, `${check.what}: the page holding the selection is shown`);
        assert.equal(hit.focused, true, `${check.what}: the selected record has focus`);
        assert.equal(hit.highlighted, true, `${check.what}: the selected record is highlighted`);
        if (check.id) assert.equal(hit.id, check.id, `${check.what}: the right record is selected`);
        if (check.org) assert.equal(hit.org, check.org, `${check.what}: a session of the right organization is selected`);
        if (check.detailOpen) assert.equal(hit.detailOpen, true, `${check.what}: its detail is open`);
        if (check.detail) {
          const text = (await page.locator(check.detail).innerText()).trim();
          assert.ok(text.length > 30 && !/Select an item/.test(text), `${check.what}: the detail panel opened (${text.slice(0, 40)})`);
        }
        const hash = await hashOf(page);
        assert.equal(hash.includes("?"), false, `${check.what}: the query is cleared once handled (${hash})`);
        console.log(`  ${check.what}: selected, focused, highlighted${check.detail || check.detailOpen ? ", detail open" : ""}, query cleared.`);
      } catch (err) { failures++; console.error(`  FAILED ${check.what}: ${err.message}`); }
    }

    // A record that is gone says so rather than landing silently on the list.
    const missing = [
      { what: "feedback", hash: "#/feedback?id=999999901", page: "feedback" },
      { what: "api key", hash: "#/api-keys?id=deep-link-smoke-missing", page: "api-keys" },
      { what: "announcement", hash: "#/announcements?id=999999902", page: "announcements" },
      { what: "autopatch", hash: "#/autopatch?id=999999903", page: "autopatch" },
      { what: "user", hash: "#/users?q=nobody-deep-link-smoke%40example.invalid", page: "users" },
      { what: "support session", hash: "#/support-sessions?id=deep-link-smoke-missing", page: "support-sessions" },
      { what: "job", hash: "#/jobs?id=deep-link-smoke-missing", page: "jobs" },
      { what: "alert channel", hash: "#/alert-routing?id=deep-link-smoke-missing", page: "alert-routing" },
      { what: "organization", hash: "#/customers/deep-link-smoke-missing-org", page: "customer360" },
    ];
    for (const check of missing) {
      await open(page, check.hash, check.page);
      try {
        if (check.page === "customer360") {
          const text = await page.locator('[data-page="customer360"] #c360Notice').innerText();
          assert.match(text, /no longer exists/i, "organization: the 360 page says the tenant is gone");
          console.log("  missing organization: explained in place.");
          continue;
        }
        const shown = await note(page);
        assert.ok(shown, `${check.what}: a missing-record note is shown`);
        assert.match(shown.text, /This item no longer exists/i, `${check.what}: the note says the item is gone`);
        assert.equal(shown.page, check.page, `${check.what}: the note is on the ${check.page} page`);
        assert.equal(shown.focused, true, `${check.what}: the note takes focus`);
        console.log(`  missing ${check.what}: clear note, focused.`);
      } catch (err) { failures++; console.error(`  FAILED missing ${check.what}: ${err.message}`); }
    }

    // Back and forward keep working, and coming back does not act on the record again.
    await open(page, `#/announcements?id=${announcement.id}`, "announcements");
    assert.equal(await hashOf(page), "#/announcements", "the handled query is replaced, not pushed");
    await page.goBack();
    await page.waitForFunction(() => location.hash === "#/dashboard", null, { timeout: 15000 });
    await page.goForward();
    await page.waitForFunction(() => location.hash === "#/announcements", null, { timeout: 15000 });
    await page.waitForTimeout(1200);
    assert.equal(await hashOf(page), "#/announcements", "forward returns to the page without the record query");
    assert.equal(await page.locator('[data-page="announcements"]').isVisible(), true, "forward renders the announcements page");
    console.log("Back and forward keep working; the cleared query does not re-trigger.");

    // The link as it arrives from an alert: opened cold, the record is selected once the
    // operator's credential connects.
    const cold = await context.newPage();
    cold.on("pageerror", error => errors.push("cold: " + error.message));
    await cold.goto(`${base}/vendor-admin/#/feedback?id=${feedback.id}`);
    await cold.locator("#platformKey").fill(key);
    await cold.locator("#loadBtn").click();
    await cold.waitForFunction(() => !!document.querySelector('[data-page="feedback"] [data-deep-link-selected]'), null, { timeout: 60000 });
    const coldHit = await selected(cold);
    assert.equal(coldHit.id, String(feedback.id), "a link opened cold selects the record");
    assert.equal(coldHit.focused, true, "a link opened cold moves focus to the record");
    assert.equal(await hashOf(cold), "#/feedback", "a link opened cold clears its query");
    await cold.close();
    console.log("A deep link opened cold (sign-in first) selects the record.");

    // A deep link to an item the loaded page does not hold. The list response is filtered here so
    // the console has to fall back to GET /platform/feedback/{id}; that request is not intercepted,
    // so the fallback is a real round trip. Without it this link was indistinguishable from a link
    // to a deleted item.
    if (longFeedback) {
      const hidden = String(longFeedback.id);
      const filterList = async route => {
        if (/\/platform\/feedback\/\d+$/.test(new URL(route.request().url()).pathname)) return route.continue();
        const response = await route.fetch();
        const body = await response.json();
        if (Array.isArray(body.items)) body.items = body.items.filter(item => String(item.id) !== hidden);
        await route.fulfill({ response, body: JSON.stringify(body), contentType: "application/json" });
      };
      await page.route("**/platform/feedback**", filterList);
      try {
        await open(page, `#/feedback?id=${hidden}`, "feedback");
        const hit = await selected(page);
        assert.ok(hit, "an item outside the loaded list is still selected");
        assert.equal(hit.id, hidden, "the right item is selected");
        assert.equal(hit.page, "feedback", "the selection is on the feedback page");
        assert.equal(hit.focused, true, "it takes focus");
        assert.equal(hit.detailOpen, true, "its folded message is opened");
        assert.equal(await note(page), null, "an item that exists gets no 'no longer exists' note");
        assert.equal((await hashOf(page)).includes("?"), false, "the query is cleared once handled");
        console.log("  feedback outside the loaded list: read on its own, selected, detail open.");

        // And with the same interception in place, one that really is gone still says so.
        await open(page, "#/feedback?id=999999904", "feedback");
        const gone = await note(page);
        assert.ok(gone, "a deleted feedback item still gets a note");
        assert.match(gone.text, /This item no longer exists/i, "the note says the item is gone");
        console.log("  feedback that is really gone: still a clear note.");
      } catch (err) { failures++; console.error(`  FAILED feedback single-item deep link: ${err.message}`); }
      await page.unroute("**/platform/feedback**", filterList);
    }

    assert.deepEqual(errors, [], "no page errors");
    await context.close();
  } finally {
    await browser.close();
    for (const [what, run] of cleanup.reverse()) {
      const res = await run();
      console.log(`Cleanup ${what}: ${res.ok ? "removed" : `failed (${res.status})`}`);
    }
  }
  if (failures) throw new Error(`${failures} deep-link check(s) failed.`);
  console.log("Deep-link smoke passed.");
}

main().catch(error => { console.error(error); process.exit(1); });
