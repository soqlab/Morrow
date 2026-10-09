/* Customer policy state is observed, never inferred from an animation or a configured API key. */
(() => {
  let stripGeneration = 0;
  const modeName = mode => ({off:"AI off",customer_hosted:"Customer-hosted AI",approved_external:"Approved external AI"}[mode] || "AI state unknown");
  const stamp = value => value ? new Date(typeof value === "number" ? value * 1000 : value).toLocaleString() : "No observation";
  function paintStrip(text) {
    const strip = document.getElementById("dataControlStrip");
    if (strip) strip.innerHTML = `<strong>Data Control</strong><span>${H(text)}</span><a href="#data-control">Review boundary &amp; access</a>`;
  }
  window.clearDataControlStrip = () => { ++stripGeneration; paintStrip("State unknown - sign in to inspect your organization"); };
  window.refreshDataControlStrip = async () => {
    const current = ++stripGeneration;
    paintStrip("Checking organization policy...");
    try {
      const data = await api("/ai-control/status");
      if (current !== stripGeneration) return;
      paintStrip(`${modeName(data.policy.mode)} / ${data.policy.free_text ? "Free text permitted" : "Metadata only"} / Policy v${data.policy.version} / Checked ${stamp(Date.now()/1000)}`);
    } catch {
      if (current === stripGeneration) paintStrip("State unavailable - no protection claim");
    }
  };

  VIEWS["data-control"] = async host => {
    host.innerHTML = '<div class="dc-workspace"><p role="status">Loading your data boundary...</p></div>';
    const root = host.firstElementChild;
    let snapshot, support, history, generation = 0, reviewed = null, receipts = [], nextBefore = null, model = null;
    const admin = (S.ctx?.actor_role || S.role) === "admin" && !SUPPORT.active;
    const message = (text, error = false) => {
      const node = root.querySelector("#dcMessage");
      if (node) { node.textContent = text; node.classList.toggle("dc-error", error); }
    };
    function download(name, data, type="application/json") {
      const url = URL.createObjectURL(data instanceof Blob ? data : new Blob([JSON.stringify(data, null, 2)], {type}));
      const link = document.createElement("a"); link.href = url; link.download = name; link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    }
    const selected = (a,b) => a === b ? "selected" : "";
    const checked = value => value ? "checked" : "";
    async function load() {
      const version = ++generation;
      const [data, access, visits, log, provider] = await Promise.all([
        api("/ai-control/status"), api("/org/support-access").catch(()=>null),
        api("/org/support-access/history").catch(()=>null), api("/ai-control/events?limit=50"),
        api("/ai-control/provider").catch(()=>null)
      ]);
      if (!root.isConnected || version !== generation) return;
      snapshot = data; support = access; history = visits; receipts = log.items; nextBefore = log.next_before; model = provider;
      reviewed = null;
      render();
      window.refreshDataControlStrip();
    }
    function renderEvents() {
      root.querySelector("#dcEvents").innerHTML = receipts.length ? `<div class="dc-table"><table><thead><tr><th>When</th><th>Observation</th><th>Scope</th><th>Receipt</th></tr></thead><tbody>${receipts.map((item,index) => {
        const d = item.data;
        return `<tr><td>${H(stamp(d.created_at))}</td><td>${H(d.event_type)}</td><td>Policy v${H(d.policy_version)}<br>${H(d.purpose || d.actor || "Organization policy")}${d.destination ? `<br>${H(d.destination)}` : ""}</td><td><details><summary>Inspect signed record</summary><pre>${H(JSON.stringify(item,null,2))}</pre></details><button type="button" class="btn sm" data-dc="receipt" data-index="${index}">Download</button></td></tr>`;
      }).join("")}</tbody></table></div>` : '<p>No retained gateway receipts. This is not proof of zero data transfers.</p>';
      root.querySelector("#dcMore").disabled = !nextBefore;
    }
    /* The active model provider, as the server resolved it -- not as the form was
     * filled in. "Unavailable" is printed when the endpoint could not be read, so a
     * blank panel never reads as "no provider". */
    const yesNo = value => value === true ? "yes" : value === false ? "no" : "unknown";
    function modelSection() {
      if (!model) return `<section class="dc-section"><header><span class="dc-kicker">06 / Model provider</span><h3>Which model answers.</h3></header><div><p>Provider state unavailable. No claim is made about what would answer.</p></div></section>`;
      const active = model.active || {}, over = model.organization_override || {}, totals = (model.usage||{}).totals || {};
      const rows = (model.capability_matrix || []).map(row =>
        `<tr><td>${H(row.provider)}</td><td>${H(row.default_model || "-")}</td><td>${H(String(row.tools))}</td><td>${H(String(row.streaming))}</td><td>${H(String(row.context_window ?? "unknown"))}</td><td>${H(row.notes || "")}</td></tr>`).join("");
      const sent = (model.data_sent || {});
      return `<section class="dc-section"><header><span class="dc-kicker">06 / Model provider</span><h3>Which model answers.</h3><p>Any hosted API, any self-hosted endpoint, or your own code. Changing the destination or the model needs a fresh policy approval in section 01.</p></header><div>
        <div class="dc-model"><div><span>ACTIVE PROVIDER</span><strong>${H(active.provider || "unknown")}</strong></div><div><span>MODEL</span><strong>${H(active.model || "unknown")}</strong></div><div><span>TOOL CALLING</span><strong>${H(yesNo(active.tools))}</strong></div><div><span>STREAMING</span><strong>${H(yesNo(active.streaming))}</strong></div><small>${active.network === false ? "Built-in rules: no model call leaves this deployment." : `Destination ${H(active.endpoint || "not resolved")}`}<br>Selected by ${H(model.selected || "?")}${model.selected_is_active === false ? " (not active: see the notes below)" : ""}${model.disabled ? " / PQC_LLM_DISABLED=1, which an organization cannot override" : ""}</small></div>
        ${(model.notes || []).length ? `<p class="dc-warning">${(model.notes||[]).map(H).join(" ")}</p>` : ""}
        <div class="dc-actions"><button class="btn" type="button" data-dc="providerTest" ${admin ? "" : "disabled"}>Send a test prompt</button><button class="btn" type="button" data-dc="providerClear" ${admin && over.configured ? "" : "disabled"}>Use the deployment's provider</button></div>
        <pre id="dcProviderTest" hidden></pre>
        <p class="dc-note">A test prompt is a real model call: it crosses the same boundary, is receipted, and may be billed by your provider. ${admin ? "" : "Only an organization admin can test or change the provider."}</p>
        <details><summary>Your own provider and key</summary><form id="dcProvider"><fieldset ${admin && !model.disabled ? "" : "disabled"}><div class="dc-fields">
          <label>Provider<select name="provider">${(over.selectable || []).map(v=>`<option value="${v}" ${selected(over.provider,v)}>${H(v)}</option>`).join("")}</select></label>
          <label>Model<input name="model" maxlength="512" value="${H(over.model || "")}" placeholder="e.g. llama3.1"></label>
          <label>Base URL<input name="base_url" maxlength="512" value="${H(over.base_url || "")}" placeholder="https://host/v1"></label>
          <label>API version (Azure)<input name="api_version" maxlength="64" value="${H(over.api_version || "")}"></label>
          <label>Deployment (Azure)<input name="deployment" maxlength="256" value="${H(over.deployment || "")}"></label>
          <label>API key<input name="api_key" type="password" maxlength="4096" autocomplete="off" placeholder="${over.api_key_present ? "stored - leave blank to keep it" : "not stored"}"></label>
        </div><p class="dc-note">The key is sealed with this deployment's vault key and is never returned by any endpoint. ${over.extra_header_names?.length ? `Stored gateway headers: ${H(over.extra_header_names.join(", "))}.` : ""} Your organization can read and set only its own provider.</p>
        <div class="dc-actions"><button class="btn" type="submit">Save this organization's provider</button></div></fieldset></form>
        <p class="dc-note">Bringing your own model in code (PQC_LLM_PROVIDER=custom) is an operator-side setting, not a per-organization one: it names Python this server imports. See docs/AI_PROVIDERS.md.</p></details>
        <details><summary>What reaches the model</summary><ul>${(sent.sent||[]).map(x=>`<li>${H(x)}</li>`).join("")}</ul><p><strong>Never sent:</strong></p><ul>${(sent.never_sent||[]).map(x=>`<li>${H(x)}</li>`).join("")}</ul><p class="dc-note">${H(sent.metadata_only_mode || "")}</p></details>
        <details><summary>What each provider supports</summary><div class="dc-table"><table><thead><tr><th>Provider</th><th>Default model</th><th>Tools</th><th>Streaming</th><th>Context</th><th>Notes</th></tr></thead><tbody>${rows}</tbody></table></div></details>
        <p>Token use in this process: ${H(String(totals.requests ?? 0))} request(s), ${H(String(totals.input_tokens ?? 0))} in / ${H(String(totals.output_tokens ?? 0))} out. Cost ${totals.cost_usd == null ? "<strong>unknown</strong> (no price configured for this model, and the provider did not report one)" : `approximately $${H(String(totals.cost_usd))} (${H(String(totals.cost_known_for))} of ${H(String(totals.requests))} priced)`}. Not billing; your provider's invoice is authoritative.</p>
      </div></section>`;
    }

    function render() {
      const p = snapshot.policy;
      root.innerHTML = `<header class="dc-hero"><div><span class="dc-kicker">Your data / your decision</span><h2>Trust should be<br>inspectable.</h2><p>Choose what the AI can receive. See which destination is approved. Stop it without waiting for us.</p><a href="/ui/ai-trust.html" target="_blank" rel="noopener">Read the AI data boundary</a></div><div class="dc-boundary"><div><span>01 / PROCESSING</span><strong>${H(modeName(p.mode))}</strong></div><div><span>02 / DATA PERMISSION</span><strong>${p.free_text ? "Free text approved" : "Metadata only"}</strong></div><div><span>03 / SUPPORT</span><strong>${support ? support.allowed ? "Customer-enabled" : "Not permitted" : "Unknown"}</strong></div><small>Policy v${H(p.version)} &middot; ${H(p.organization_id)}<br>Snapshot checked ${H(stamp(Date.now()/1000))}. Not continuous monitoring.</small></div></header>
        <div class="dc-actions"><button type="button" class="btn" data-dc="refresh">Refresh evidence</button><button type="button" class="btn" data-dc="stop" ${admin ? "" : "disabled"}>Stop AI now</button><button type="button" class="btn" data-dc="kit">Download local filtering kit</button></div>
        <p id="dcMessage" class="dc-message" role="status" aria-live="polite"></p>
        <p class="dc-note">Stopping blocks new and queued calls, not already-dispatching requests. The assistant is read-only. Scanning and other non-AI integrations remain separate. ${admin ? "" : "Only an organization admin can change these controls."}</p>
        <section class="dc-section"><header><span class="dc-kicker">01 / Permission</span><h3>Approve a boundary.</h3><p>No silent provider fallback. Broader permissions, endpoint changes and model changes need approval.</p></header><div><form id="dcPolicy"><fieldset ${admin ? "" : "disabled"}><div class="dc-fields"><label>Processing mode<select name="mode"><option value="off" ${selected(p.mode,"off")}>Off</option><option value="customer_hosted" ${selected(p.mode,"customer_hosted")}>Customer-hosted</option><option value="approved_external" ${selected(p.mode,"approved_external")}>Approved external provider</option></select></label><label>External provider<select name="provider">${[["openai","openai"],["anthropic","anthropic"],["byo",`byo - your own provider${snapshot.destinations.byo?.provider ? ` (${snapshot.destinations.byo.provider})` : ""}`]].map(([v,label])=>`<option value="${v}" ${selected(p.provider,v)}>${H(label)}${snapshot.destinations[v]?.configured ? "" : " (not configured)"}</option>`).join("")}</select></label><label>Receipt retention (days)<input name="retention" type="number" min="1" max="365" value="${p.receipt_retention_days}" required></label></div><fieldset><legend>Permitted workflows</legend><div class="dc-checks">${["assistant","intent","metadata_analysis","remediation"].map(v=>`<label class="dc-check"><input type="checkbox" name="workflow" value="${v}" ${checked(p.workflows.includes(v))}>${H(v.replaceAll("_"," "))}</label>`).join("")}</div></fieldset><label class="dc-check dc-warning"><input name="freeText" type="checkbox" ${checked(p.free_text)}>Allow free text, including code and identifiers. Credential-pattern checks are NOT complete DLP. Keep this off for metadata-only processing.</label><div class="dc-actions"><button class="btn" type="submit">Review exact policy</button></div></fieldset></form><div id="dcReview"></div></div></section>
        <section class="dc-section"><header><span class="dc-kicker">02 / Inspect</span><h3>See the outgoing data.</h3><p>This web preview reaches the platform, but not the model. Use the downloaded kit for offline review before ANY raw data leaves your environment.</p></header><div><form id="dcPreview"><label>Cryptographic metadata (JSON)<textarea name="metadata" rows="5" maxlength="64000" placeholder='{"assets":[{"algorithm":"RSA","key_bits":2048,"hostname":"removed.example"}]}' required></textarea></label><div class="dc-actions"><button class="btn" type="submit">Preview model payload</button></div></form><pre id="dcPreviewResult" hidden></pre></div></section>
        <section class="dc-section"><header><span class="dc-kicker">03 / Human access</span><h3>Support is your choice.</h3><p>Controls vendor support sessions, not direct infrastructure administrator access. Revoking ends active sessions.</p></header><div><p>${support ? `Vendor support sessions: <strong>${support.allowed ? "permitted" : "not permitted"}</strong>. ${support.default ? "No explicit setting; access denied by default." : `Last changed ${H(stamp(support.updated_at))}.`}` : "Support access state unavailable. No assumptions made."}</p><form id="dcSupport"><label>Reason<input name="reason" minlength="8" maxlength="300" required placeholder="Ticket or reason for this decision"></label><div class="dc-actions"><button class="btn" ${admin && support ? "" : "disabled"}>${support?.allowed ? "Revoke support access" : "Permit support sessions"}</button></div></form>${history ? history.items.length ? `<div class="dc-table"><table><thead><tr><th>Operator</th><th>Session</th><th>Recorded requests</th></tr></thead><tbody>${history.items.map(item=>`<tr><td>${H(item.operator_display || item.operator_id || item.operator || "Support")}</td><td>${H(item.status || "Recorded")}<br>${H(stamp(item.created_at))}</td><td>${H(item.requests_total || 0)}<details><summary>Inspect access history</summary><pre>${H(JSON.stringify(item,null,2))}</pre></details></td></tr>`).join("")}</tbody></table></div>` : "<p>No recorded support sessions.</p>" : "<p>Support history unavailable.</p>"}</div></section>
        <section class="dc-section"><header><span class="dc-kicker">04 / Evidence</span><h3>Receipts, not promises.</h3><p>Signed gateway observations. No prompt bodies or model outputs stored in these receipts. Auth rejections and deterministic AI-off responses are not model dispatches.</p></header><div><div class="dc-actions"><button class="btn" type="button" data-dc="export">Export newest 1,000 receipts</button><button class="btn" type="button" data-dc="key" ${snapshot.public_key ? "" : "disabled"}>Download verification key</button></div><p class="dc-note">Pin this key via an independent trusted channel. Use the kit's verifier; a signature authenticates records, not provider deletion or a complete history of network transfers. Ed25519 is not a PQC or zero-knowledge proof.</p><div id="dcEvents"></div><button id="dcMore" class="btn" type="button" data-dc="more">Load older receipts</button></div></section>
        <section class="dc-section"><header><span class="dc-kicker">05 / Limits</span><h3>What we cannot attest.</h3></header><div><p>Provider retention and training settings: <strong>not verified</strong>. Customer-hosted location: <strong>operator-declared, not remotely attested</strong>. Complete outbound network enforcement: <strong>requires deployment firewall controls</strong>.</p><p>Latest recorded dispatch authorization: ${H(stamp(snapshot.last_enforcement_check))}. ${snapshot.observation === "recent_dispatch" ? "Recent gateway observation only." : "No recent dispatch evidence; current enforcement coverage is unknown or stale."}</p><p class="dc-note">Receipt retention excludes expired records on reads; running-server maintenance deletes bounded batches each minute. Provider logs, backups and other platform journals have separate retention policies. These controls are not a certification or a claim that all platform data stays local.</p></div></section>
        ${modelSection()}`;
      renderEvents();
      root.querySelector("#dcPolicy").addEventListener("input", () => { reviewed=null; root.querySelector("#dcReview").textContent="Policy edited. Review again before approval."; });
      root.querySelector("#dcPolicy").addEventListener("submit", async event => {
        event.preventDefault();
        await work(async () => {
          const form = new FormData(event.target), mode = form.get("mode");
          const proposal = {expected_version: p.version, policy:{mode, provider:mode === "off" ? "none" : mode === "customer_hosted" ? "local" : form.get("provider"), workflows:form.getAll("workflow"), free_text:form.get("freeText") === "on", receipt_retention_days:Number(form.get("retention"))}};
          reviewed = null;
          const result = await api("/ai-control/policy/review", {method:"POST",body:proposal});
          // Do not let edits made during a request approve a different visible form.
          if (JSON.stringify([...new FormData(event.target)]) !== JSON.stringify([...form])) return message("Form changed during review. Review again.", true);
          reviewed = {...proposal, review_hash:result.review_hash};
          root.querySelector("#dcReview").innerHTML = `<p class="dc-warning">${H(result.notice)}</p><pre>${H(JSON.stringify(result,null,2))}</pre><button class="btn" type="button" data-dc="approve">Approve this exact policy</button>`;
        });
      });
      root.querySelector("#dcPreview").addEventListener("submit", async event => {
        event.preventDefault(); await work(async()=> {
          const metadata = JSON.parse(new FormData(event.target).get("metadata"));
          const result = await api("/ai-control/preview",{method:"POST",body:{purpose:"metadata_analysis",metadata}});
          const output=root.querySelector("#dcPreviewResult"); output.hidden=false; output.textContent=JSON.stringify(result,null,2);
        });
      });
      root.querySelector("#dcProvider")?.addEventListener("submit", async event => {
        event.preventDefault(); await work(async()=> {
          const form = new FormData(event.target), body = {provider: form.get("provider")};
          for (const field of ["model","base_url","api_version","deployment","api_key"]) {
            const value = String(form.get(field) || "").trim();
            if (value) body[field] = value;
          }
          await api("/ai-control/provider",{method:"PUT",body});
          await load();
          message("Provider saved. The destination and model changed, so approve the policy again in section 01 before the next model call.");
        });
      });
      root.querySelector("#dcSupport").addEventListener("submit", async event => {
        event.preventDefault(); await work(async()=> {
          await api("/org/support-access",{method:"PUT",body:{allowed:!support.allowed,reason:new FormData(event.target).get("reason")}});
          await load(); message("Support access updated.");
        });
      });
    }
    let busy = 0;
    async function work(fn, priority = false) {
      if (busy && !priority) return; busy++;
      try { message("Working..."); await fn(); if(root.isConnected && root.querySelector("#dcMessage")?.textContent === "Working...") message("Done."); }
      catch(error) { message(error.message,true); }
      finally { busy--; }
    }
    root.addEventListener("click", event => {
      const button=event.target.closest("[data-dc]"); if(!button || button.disabled) return;
      work(async()=> {
        switch(button.dataset.dc) {
          case "refresh": await load(); break;
          case "approve": if(!reviewed) throw new Error("Review the policy first"); await api("/ai-control/policy",{method:"PUT",body:reviewed}); await load(); message("Policy approved. New model calls use this boundary."); break;
          case "stop": { const result=await api("/ai-control/stop",{method:"POST"}); await load(); message(`AI stopped. ${result.cancelled} queued calls cancelled. ${result.receipt_recorded ? "Signed receipt recorded." : "No signed stop receipt recorded."} Already-dispatching calls cannot be recalled.`); break; }
          case "export": download("ai-processing-receipts.json",await api("/ai-control/export")); break;
          case "key": download("pinned-key.txt",new Blob([snapshot.public_key],{type:"text/plain"})); message("Confirm this key through an independent trusted channel before trusting signatures."); break;
          case "receipt": download("ai-receipt.json",{receipts:[receipts[Number(button.dataset.index)]]}); break;
          case "more": { const page=await api(`/ai-control/events?limit=50&before=${encodeURIComponent(nextBefore)}`); receipts.push(...page.items); nextBefore=page.next_before; renderEvents(); break; }
          case "providerTest": {
            const output = root.querySelector("#dcProviderTest");
            const result = await api("/ai-control/provider/test",{method:"POST",body:{prompt:"Reply with the single word: ready."}});
            output.hidden = false; output.textContent = JSON.stringify(result,null,2);
            message(result.ok ? `${result.provider} / ${result.answered_by_model || result.model} answered.` : `${result.provider} did not answer: ${result.error?.message || "unknown"} ${result.error?.remedy || ""}`, !result.ok);
            break;
          }
          case "providerClear": { await api("/ai-control/provider",{method:"DELETE"}); await load(); message("This organization now uses the deployment's own provider. Approve the policy again in section 01."); break; }
          case "kit": { await api("/ai-control/status"); const response=await rawFetch("/ai-control/customer-kit",{method:"GET",timeout:45000}); if(!response.ok) throw new Error("Customer kit unavailable; refresh authentication and retry"); download("customer-data-control.zip",await response.blob()); break; }
        }
      }, button.dataset.dc === "stop");
    });
    await load();
  };
})();
