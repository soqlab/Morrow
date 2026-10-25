/* The gateway workspace uses the existing console's authenticated API client. */
VIEWS.gateway = async host => {
  host.innerHTML = '<section class="gatewayWorkspace"><p role="status">Loading gateway sites...</p></section>';
  const root = host.firstElementChild;
  let sites = [], selected = null, generation = 0, expiryTimer = 0;
  const role = S.ctx?.actor_role || S.role;
  const admin = ["admin", "owner"].includes(role);
  const write = ["operator", "admin", "owner"].includes(role);
  const stamp = value => value ? new Date(value * 1000).toLocaleString() : "Not checked";
  const state = value => `<span class="gw-state ${["verified", "observe", "enforce", "passed"].includes(value) ? "gw-confirmed" : ""}">${H(String(value || "unknown").replaceAll("_", " "))}</span>`;
  const button = (label, action, allowed = write, extra = "") => `<button type="button" class="btn sm" data-gw="${action}" ${allowed ? "" : "disabled"} ${extra}>${label}</button>`;
  function message(text, error = false) {
    const status = root.querySelector("#gwMessage");
    if (status) { status.textContent = text; status.classList.toggle("gw-error", error); }
  }
  function download(name, value) {
    const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: "application/json" }));
    const a = document.createElement("a"); a.href = url; a.download = name; a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  async function load(id = selected?.id) {
    const current = ++generation;
    const data = await api("/gateway/sites");
    if (!root.isConnected || current !== generation) return;
    sites = data.items; selected = sites.find(site => site.id === id) || sites[0] || null;
    render();
    if (selected) {
      const siteID = selected.id;
      const history = await api(`/gateway/sites/${siteID}/history`);
      if (!root.isConnected || selected?.id !== siteID || current !== generation) return;
      root.querySelector("#gwHistory").innerHTML = history.items.map(row => `<tr><td>v${row.version}</td><td>${state(row.policy.mode)}</td><td>${H(row.actor)}</td><td>${H(row.reason)}</td><td>${H(stamp(row.created_at))}</td><td>${button("Restore", "rollback", admin, `data-version="${row.version}"`)}</td></tr>`).join("");
    }
  }
  function render() {
    clearTimeout(expiryTimer);
    const site = selected, policy = site?.policy, coverage = site?.coverage;
    root.innerHTML = `<header class="gw-intro"><div class="gw-intro-copy"><span class="eyebrow">WEBSITE GATEWAY / CUSTOMER CONTROLLED</span><h2>Your website.<br>A controlled perimeter.</h2><p>Connect without rewriting application code. Adding a site does not reroute traffic: ownership, deployment, DNS, and runtime checks remain separate steps.</p></div><figure class="gw-scene"></figure></header>
      <p id="gwMessage" role="status" aria-live="polite"></p>
      <form id="gwCreate" class="gw-connect"><label>Public website<input name="website" placeholder="https://www.your-company.com" required maxlength="300" ${write ? "" : "disabled"}></label><label>Separate origin hostname<input name="origin" placeholder="https://origin.your-company.com" required maxlength="300" ${write ? "" : "disabled"}></label><button class="btn pri" ${write ? "" : "disabled"}>Add website</button></form>
      <div class="gw-layout"><nav class="gw-sites" aria-label="Gateway websites">${sites.length ? sites.map(item => `<button type="button" data-site="${H(item.id)}" aria-current="${item.id === site?.id ? "true" : "false"}"><strong>${H(item.hostname)}</strong><span>${H(item.coverage.filtering.replaceAll("_", " "))}</span></button>`).join("") : "No websites added yet."}</nav><div class="gw-detail">${site ? `
      <section class="gw-section" id="gwCoverageSection"><div class="gw-heading"><div><span class="eyebrow">01 / PROTECTION COVERAGE</span><h3>${H(site.hostname)}</h3></div>${button("Refresh evidence", "refresh", true)}</div>
        <dl class="gw-coverage">${Object.entries(coverage).filter(([key]) => key !== "basis").map(([key, value]) => `<div><dt>${H(key.replaceAll("_", " "))}</dt><dd data-coverage="${H(key)}">${state(value)}</dd></div>`).join("")}</dl>
        <p class="gw-note">${H(coverage.basis)}. Runtime evidence expires after 5 minutes. No background polling.</p>
        ${site.runtime_error ? `<p class="gw-error">${H(site.runtime_error)}</p>` : ""}
        <p class="gw-note">Desired policy v${policy.version}; last runtime check: ${H(stamp(site.runtime?.checked_at))}. Neither a generated policy nor an old observation counts as active filtering.</p></section>
      <section class="gw-section" id="gwOwnershipSection"><span class="eyebrow">02 / OWNERSHIP &amp; DEPLOYMENT</span><h3>Authorize the connection.</h3><p>Add these TXT records for both the public site and origin. No web requests are sent until ownership is verified.</p>
        <div class="gw-table"><table><thead><tr><th>Type</th><th>DNS name</th><th>Value</th></tr></thead><tbody>${site.dns_records.map(record => `<tr><td>TXT</td><td><code>${H(record.name)}</code></td><td><code>${H(record.value)}</code></td></tr>`).join("")}</tbody></table></div>
        <div class="row">${button("Verify ownership", "ownership")}${button(site.key_configured ? "Rotate provisioning credential" : "Download provisioning bundle", "bootstrap", admin)}${button("Download desired policy", "download", admin)}</div>
        <details class="gw-guide"><summary>Deployment, privacy boundary &amp; recovery instructions</summary><ol><li>Deploy the separate <code>gateway/</code> runtime from this repository. It uses Coraza with OWASP CRS; the console never proxies customer traffic.</li><li>Import the downloaded bundle with <code>gateway/prepare.py</code>. Supply your production certificate and private key locally. Do not upload TLS private keys here.</li><li>Run <code>docker compose -f gateway/compose.yml up -d --build</code>. Configure your DNS/load balancer to the deployed gateway address. Automatic provider authorization is not implemented in this release.</li><li>Restrict direct origin access to approved gateway addresses or an authenticated origin connection. This console does not claim origin-bypass protection without verification.</li><li>Verify observe mode, run application checks, review rule matches, then approve enforcement. Two replicas on one host are not multi-region disaster recovery.</li><li>Restore a previous policy as a new version and apply it for policy rollback. DNS rollback is a separate customer action and depends on propagation.</li></ol><p>Filtering processes decrypted requests in gateway memory. Only bounded numeric counts and rule IDs are retained; no request bodies, URLs, IP addresses, authorization headers, or cookies are logged by this runtime. Gateway-to-origin TLS is verified. Post-quantum remains unknown until negotiation evidence is available.</p></details></section>
      <section class="gw-section" id="gwCompatSection"><span class="eyebrow">03 / COMPATIBILITY</span><h3>Check before cutover.</h3><form id="gwChecks" class="gw-checks"><label>Public paths, one per line (maximum 4)<textarea name="paths" rows="3" required>/</textarea></label><label>Expected HTTP status<input name="expected" type="number" min="200" max="499" value="200" required></label><label class="gw-consent"><input name="approved" type="checkbox" required>I approve HEAD requests to these paths. No credentials or response bodies will be retained.</label><button class="btn sm" ${write ? "" : "disabled"}>Run reachability checks</button></form>
        ${site.compatibility ? `<p class="gw-note">${H(site.compatibility.scope)} Checked ${H(stamp(site.compatibility.checked_at))}.</p><div class="gw-table"><table><thead><tr><th>Check</th><th>Result</th><th>HTTP</th><th>Latency</th></tr></thead><tbody>${site.compatibility.results.map(check => `<tr><td>${H(check.name)}</td><td>${state(check.status)} ${H(check.error || "")}</td><td>${check.http_status ?? "Unknown"}</td><td>${check.latency_ms == null ? "Unknown" : check.latency_ms + " ms"}</td></tr>`).join("")}</tbody></table></div>` : ""}
        <form id="gwJourneys"><h4>Customer application test review</h4><p class="gw-note">These are customer attestations, not automated test results. Use a staging environment and test accounts for submissions.</p>${["login", "forms", "uploads", "websocket"].map(kind => { const check = site.journey_review?.checks.find(c => c.kind === kind); return `<div class="gw-journey"><label>${H(kind)}<select name="${kind}-result" required><option value="">Not reviewed</option>${["passed", "failed", "not_applicable"].map(value => `<option value="${value}" ${check?.result === value ? "selected" : ""}>${value.replaceAll("_", " ")}</option>`).join("")}</select></label><label>Test reference or non-applicability reason<input name="${kind}-evidence" minlength="8" maxlength="300" required value="${H(check?.evidence || "")}"></label></div>`; }).join("")}<button class="btn sm" ${write ? "" : "disabled"}>Save customer review</button></form></section>
      <section class="gw-section" id="gwPolicySection"><span class="eyebrow">04 / FILTERING POLICY</span><h3>Observe. Review. Enforce.</h3><form id="gwPolicy"><div class="gw-policy-fields"><label>Desired mode<select name="mode"><option value="observe" ${policy.mode === "observe" ? "selected" : ""}>Observe - record CRS rule matches</option><option value="enforce" ${policy.mode === "enforce" ? "selected" : ""}>Enforce - apply CRS blocking rules</option></select></label><label>Metadata retention (hours)<input name="retention" type="number" min="0" max="24" value="${policy.retention_hours}" required></label><label>Request body limit (bytes)<input name="bodyLimit" type="number" min="32768" max="8388608" value="${policy.max_body_bytes}" required></label></div>
        <details><summary>Exact-path, expiring rule exceptions</summary><p class="gw-note">JSON array: rule_id, path, method, expires_at (Unix seconds), reason. Maximum 20; expiry within 7 days. No global WAF-disable exceptions.</p><textarea name="exceptions" rows="5" spellcheck="false">${H(JSON.stringify(policy.exceptions, null, 2))}</textarea></details><label>Change reason<input name="reason" required minlength="8" maxlength="200" placeholder="Why this change is approved"></label><button class="btn sm" ${admin ? "" : "disabled"}>Publish desired policy</button></form>
        <div class="row">${button("Verify running gateway", "probe")}${button("Apply published policy", "apply", admin)}</div><p class="gw-note">Apply authenticates the gateway before sending its credential. Invalid configurations retain the last known-good policy. Upstream failure returns an error, never a silent bypass.</p></section>
      <section class="gw-section" id="gwObservations"><span class="eyebrow">05 / PRIVACY-SAFE OBSERVATIONS</span><h3>Measured, not manufactured.</h3>${site.statistics ? `<p class="gw-note">${H(site.statistics.scope)}. Checked ${H(stamp(site.statistics.checked_at))}. The gateway keeps at most 10,000 metadata events; counts are not fleet-wide traffic totals.</p><dl class="gw-coverage">${["requests", "matched", "blocked", "upstream_errors"].map(key => `<div><dt>${key.replaceAll("_", " ")}</dt><dd>${NUM(site.statistics[key])}</dd></div>`).join("")}</dl><div class="gw-rule-list">${Object.entries(site.statistics.rule_counts || {}).map(([id, count]) => `<span>CRS rule ${H(id)}: ${NUM(count)} matches</span>`).join("") || "No rule matches in this observation window."}</div>` : `<p>No current gateway statistics. Zero traffic is not assumed.</p>`}${button("Erase responding gateway's statistics", "purge", admin)}</section>
      <section class="gw-section"><span class="eyebrow">06 / RECOVERY JOURNAL</span><h3>Every policy has a previous version.</h3><div class="gw-table"><table><thead><tr><th>Version</th><th>Mode</th><th>Actor</th><th>Reason</th><th>Published</th><th>Recovery</th></tr></thead><tbody id="gwHistory"><tr><td colspan="6">Loading version history...</td></tr></tbody></table></div></section>` : `<section class="gw-section"><h3>Start with a domain you control.</h3><p>Your website stays at its own address. This workspace manages configuration and checks; traffic must be routed to a separately deployed gateway.</p></section>`}</div></div>`;
    root.querySelector("#gwCreate").onsubmit = event => perform(event, async form => {
      const value = await api("/gateway/sites", { method: "POST", body: { website: form.get("website"), origin: form.get("origin") } });
      await load(value.id); message("Site added. Ownership and routing are not yet verified.");
    });
    // The perimeter map reads the coverage values rendered above, so it always
    // agrees with them, including after expireEvidence() downgrades one.
    const scene = window.airlockGatewayScene?.mount(root.querySelector(".gw-scene"), {
      site,
      preview: root.querySelector("#gwCreate [name=website]"),
      states: () => Object.fromEntries([...root.querySelectorAll("[data-coverage]")].map(el => [el.dataset.coverage, el.textContent.trim()])),
      stats: () => {
        const values = [...root.querySelectorAll("#gwObservations dd")].map(el => Number(el.textContent.replace(/,/g, "")));
        return values.length >= 3 && values.every(Number.isFinite) ? { requests: values[0], matched: values[1], blocked: values[2] } : null;
      },
      pick: key => {
        if (!site) { root.querySelector("#gwCreate [name=website]")?.focus(); return; }
        const target = root.querySelector({ ownership: "#gwOwnershipSection", routing: "#gwCoverageSection", gateway: "#gwPolicySection", origin: "#gwCompatSection" }[key]);
        if (!target) return;
        target.scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
        target.classList.remove("gw-flash"); void target.offsetWidth; target.classList.add("gw-flash");
      },
    });
    if (!site) return;
    function expireEvidence() {
      if (!root.isConnected || selected?.id !== site.id) return;
      const now = Date.now(), deadlines = [];
      if (site.runtime?.checked_at) {
        const deadline = (site.runtime.checked_at + 300) * 1000;
        if (deadline > now) deadlines.push(deadline);
        else {
          for (const key of ["routing", "certificate", "filtering"]) {
            const field = root.querySelector(`[data-coverage="${key}"]`);
            if (field) field.innerHTML = state("unknown");
          }
          if (site.statistics) {
            root.querySelectorAll("#gwObservations dd").forEach(field => { field.textContent = "Expired"; });
            root.querySelector("#gwObservations .gw-rule-list")?.replaceChildren();
          }
          message("Runtime evidence has expired. Refresh and verify again before relying on the coverage state.");
        }
      }
      if (site.ownership_verified_at) {
        const deadline = (site.ownership_verified_at + 86400) * 1000;
        if (deadline > now) deadlines.push(deadline);
        else {
          root.querySelector('[data-coverage="ownership"]').innerHTML = state("verification_required");
          root.querySelector('[data-coverage="filtering"]').innerHTML = state("unknown");
          message("Ownership verification has expired. Verify both TXT records again before operating this gateway.");
        }
      }
      if (deadlines.length) expiryTimer = setTimeout(expireEvidence, Math.min(...deadlines) - now);
      scene?.refresh();
    }
    expireEvidence();
    root.querySelector("#gwChecks").onsubmit = event => perform(event, async form => {
      const paths = form.get("paths").split(/\r?\n/).map(value => value.trim()).filter(Boolean);
      await mutation("compatibility", { approved: form.get("approved") === "on", cases: paths.map(path => ({ name: path, path, expected_status: Number(form.get("expected")) })) });
    });
    root.querySelector("#gwJourneys").onsubmit = event => perform(event, async form => {
      await mutation("journeys", { checks: ["login", "forms", "uploads", "websocket"].map(kind => ({ kind, result: form.get(kind + "-result"), evidence: form.get(kind + "-evidence") })) });
    });
    root.querySelector("#gwPolicy").onsubmit = event => perform(event, async form => {
      const body = { expected_version: policy.version, mode: form.get("mode"), retention_hours: Number(form.get("retention")), max_body_bytes: Number(form.get("bodyLimit")), exceptions: JSON.parse(form.get("exceptions")), reason: form.get("reason") };
      await mutation("policy", body, "PUT"); message("Desired policy published. Apply and verify it before claiming active protection.");
    });
  }
  async function perform(event, fn) {
    event.preventDefault(); const form = event.currentTarget, submit = event.submitter;
    if (submit) submit.disabled = true;
    message("Working...");
    try { await fn(new FormData(form)); }
    catch (error) { message(error.message, true); }
    finally { if (submit?.isConnected) submit.disabled = false; }
  }
  async function mutation(action, body, method = "POST") {
    const id = selected.id;
    await api(`/gateway/sites/${id}/${action}`, { method, body, timeout: 60000 });
    if (root.isConnected && selected?.id === id) { await load(id); message("Operation completed. Review the returned evidence and any pending steps."); }
  }
  root.onclick = async event => {
    const siteButton = event.target.closest("[data-site]");
    if (siteButton) { try { await load(siteButton.dataset.site); } catch (error) { message(error.message, true); } return; }
    const control = event.target.closest("[data-gw]"); if (!control || control.disabled || !selected) return;
    const action = control.dataset.gw;
    control.disabled = true;
    try {
      if (action === "refresh") await load();
      else if (action === "download") download("policy.json", selected.policy);
      else if (action === "bootstrap") {
        if (!confirm("Provisioning creates or rotates the gateway credential. Existing replicas must receive the new secret. Continue?")) return;
        const body = await api(`/gateway/sites/${selected.id}/bootstrap`, { method: "POST" });
        if (!root.isConnected) return;
        download("airlock-gateway-bootstrap.json", body); await load(); message("Provisioning bundle downloaded once. Keep it secret and deploy it locally; no traffic has changed.");
      } else if (action === "rollback") {
        const reason = prompt("Reason for restoring this policy as a new version (minimum 8 characters):");
        if (reason === null) return;
        await mutation("rollback", { version: Number(control.dataset.version), expected_version: selected.policy.version, reason });
        message("Rollback published as a new version. Apply it to the gateway; DNS routing is unchanged.");
      } else if (action === "apply") {
        if (!confirm("Apply this policy to the deployed gateway? Enforce mode can block real customer requests.")) return;
        await mutation("apply");
      } else if (action === "purge") {
        if (!confirm("Erase retained numeric statistics on the responding gateway process? This does not erase other replicas.")) return;
        await mutation("statistics", undefined, "DELETE");
      } else await mutation(action);
    } catch (error) { message(error.message, true); }
    finally { if (control.isConnected) control.disabled = false; }
  };
  try { await load(); } catch (error) { if (root.isConnected) root.innerHTML = `<p role="alert">Gateway data unavailable: ${H(error.message)}</p>`; }
};
