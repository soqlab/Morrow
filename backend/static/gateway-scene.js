(() => {
  "use strict";
  /* ==========================================================================
     Website Gateway perimeter map (3D, interactive).

     Visitors → ownership proof → routing → gateway gate → origin, with the
     origin inside a perimeter wall. Nothing here is a model of its own: every
     checkpoint reads the coverage value the page is showing at that moment,
     including values the page has already downgraded because their evidence
     expired. Request packets travel only as far as that verified chain allows
     and stop at the first checkpoint that is not verified. Packets bounce off
     the gate only in proportion to the gateway's own current statistics.

     Drag to orbit and tilt, arrow keys to turn, double-click to reset. Hover a
     checkpoint for its state; click it to open the section that changes it.
     ========================================================================== */

  const TAU = Math.PI * 2;
  const CONFIRMED = /^(verified|signed gateway response verified|observe|enforce|passed)$/;
  const reduced = matchMedia("(prefers-reduced-motion: reduce)");
  const still = () => reduced.matches || document.body.dataset.motion === "paused" || document.hidden;
  const clamp = (v, a, b) => Math.min(b, Math.max(a, v));
  const esc = s => String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/"/g, "&quot;");

  const HOPS = [
    { key: "ownership", name: "Ownership", role: "DNS TXT proof for the site and origin" },
    { key: "routing", name: "Routing", role: "Traffic answered through the gateway" },
    { key: "gateway", name: "Gateway", role: "Certificate and filtering" },
    { key: "origin", name: "Origin", role: "Direct access to your application" },
  ];

  function mount(figure, { site, states, stats, preview, pick }) {
    if (!figure) return null;
    figure.innerHTML = `<div class="gw3d-stage">
        <canvas tabindex="0" role="img" aria-label="Interactive 3D perimeter map. Use the checkpoint buttons below for the same information."></canvas>
        <div class="gw3d-hud"><span class="gw3d-kicker">Perimeter map</span><b class="gw3d-host"></b><span class="gw3d-verdict"></span></div>
        <div class="gw3d-tip" hidden></div>
        <span class="gw3d-hint">Drag to orbit · click a checkpoint</span>
      </div>
      <div class="gw3d-legend"></div>`;
    const canvas = figure.querySelector("canvas"), ctx = canvas.getContext("2d");
    const hud = { host: figure.querySelector(".gw3d-host"), verdict: figure.querySelector(".gw3d-verdict") };
    const tip = figure.querySelector(".gw3d-tip"), legend = figure.querySelector(".gw3d-legend");
    let W = 0, H = 0, ratio = 1, raf = 0, last = 0, clock = 0, visible = true;
    let yaw = -.2, tilt = .82, yawTarget = -.2, tiltTarget = .82, touchedAt = -1e9;
    let drag = null, hover = null, hits = [], model = null, P = palette();

    function palette() {
      const s = getComputedStyle(figure), v = (name, fallback) => s.getPropertyValue(name).trim() || fallback;
      return {
        ok: v("--ok", "#4FB58B"), warn: v("--warn", "#D4913F"), bad: v("--bad", "#E46E62"), brand: v("--brand", "#7B6BFF"),
        ink: v("--ink", "#E9EDF4"), ink2: v("--ink2", "#B8C0CC"), ink3: v("--ink3", "#8A94A6"),
        line: v("--line", "#1A2130"), ground: v("--surface", "#0A0E15"),
      };
    }

    /* The state of every checkpoint, straight from what the page shows. */
    function read() {
      const s = site ? states() : {};
      const ok = key => CONFIRMED.test(String(s[key] || "").trim());
      const hop = {
        ownership: { ok: ok("ownership"), text: s.ownership || "no website yet" },
        routing: { ok: ok("routing"), text: s.routing || "unknown" },
        gateway: { ok: ok("certificate") && ok("filtering"), text: `certificate ${s.certificate || "unknown"} · filtering ${s.filtering || "unknown"}` },
        origin: { ok: /^verified$/.test(String(s.origin_bypass || "")), text: `direct access ${s.origin_bypass || "not verified"}` },
      };
      // How far a request gets: 0 nowhere, 1 ownership, 2 routing, 3 gateway, 4 origin.
      const reach = !site ? 0 : !hop.ownership.ok ? 1 : !hop.routing.ok ? 2 : !hop.gateway.ok ? 3 : 4;
      const numbers = site && stats ? stats() : null;
      const blockedShare = numbers && numbers.requests > 0 ? clamp(numbers.blocked / numbers.requests, 0, 1) : 0;
      const matchedShare = numbers && numbers.requests > 0 ? clamp(numbers.matched / numbers.requests, 0, 1) : 0;
      const stopped = reach > 0 && reach < 4 ? HOPS[reach - 1] : null;
      const verdict = !site ? "Add a website to map its perimeter"
        : reach === 4 ? "Requests reach the origin through the gateway"
        : `Requests stop at ${stopped.name.toLowerCase()} · ${hop[stopped.key].text}`;
      const hostname = site?.hostname || hostFromInput() || "your website";
      return { hop, reach, blockedShare, matchedShare, numbers, verdict, hostname, mode: s.filtering || s.desired_mode || "" };
    }
    function hostFromInput() {
      const raw = preview?.value?.trim();
      if (!raw) return "";
      try { return new URL(/^https?:\/\//i.test(raw) ? raw : "https://" + raw).hostname; } catch { return ""; }
    }

    function refresh() {
      model = read();
      hud.host.textContent = model.hostname;
      hud.verdict.textContent = model.verdict;
      hud.verdict.dataset.tone = !site ? "idle" : model.reach === 4 ? "ok" : "warn";
      legend.innerHTML = HOPS.map((h, i) => {
        const st = model.hop[h.key], reached = model.reach > i;
        const tone = !site ? "idle" : st.ok ? "ok" : reached || model.reach === i + 1 ? "warn" : "idle";
        return `<button type="button" data-hop="${h.key}" data-tone="${tone}"><i aria-hidden="true"></i>
          <span>${esc(h.name)}</span><b>${esc(site ? st.text : "waiting for a website")}</b></button>`;
      }).join("");
      wake();
    }

    /* ---------- drawing ---------- */
    function layout() {
      const ring = { x: W * .74, y: H * .52, r: Math.min(W * .17, H * .4) };
      return {
        ring,
        visitors: [-.3, -.15, 0, .15, .3].map((o, i) => ({ x: W * (.07 + (i % 2) * .025), y: H * (.52 + o) })),
        ownership: { x: W * .3, y: H * .52 },
        routing: { x: (W * .3 + ring.x - ring.r) / 2, y: H * .52 },
        gateway: { x: ring.x - ring.r, y: ring.y },
        origin: { x: ring.x, y: ring.y },
      };
    }

    function draw() {
      if (!W || !H || !model) return;
      ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
      ctx.clearRect(0, 0, W, H);
      const space = window.airlockSpace;
      if (!space) return;
      // The fit covers the orbit range, so dragging never zooms; a narrower range keeps the scene large.
      const g = space.view(ctx, W, H, { tilt: Math.round(tilt * 50) / 50, yaw, yawRange: .6, lift: 16, pad: .02, inset: [.02, .12] });
      const L = layout(), m = model, moving = !still();
      g.floorGrid(28, P.line, P.ground);

      const hopTone = (i, key) => (!site ? P.ink3 : m.hop[key].ok ? P.ok : m.reach === i + 1 ? P.warn : P.ink3);
      const wallTone = !site ? P.ink3 : m.hop.gateway.ok ? P.ok : P.warn;

      // The ground inside the perimeter.
      g.lift = 0;
      const inside = space.tint(wallTone, .07);
      if (inside) { ctx.fillStyle = inside; g.beginPath(); g.arc(L.ring.x, L.ring.y, L.ring.r, 0, TAU); g.fill(); }
      g.lift = g.base;

      // The perimeter wall, with an opening for the gate. Far segments first.
      const segs = [];
      const N = 40, gap = .3;
      for (let i = 0; i < N; i++) {
        const a0 = i / N * TAU, a1 = (i + 1) / N * TAU, mid = (a0 + a1) / 2;
        if (Math.abs(((mid - Math.PI) + TAU) % TAU - (mid > Math.PI ? 0 : 0)) < gap && Math.abs(mid - Math.PI) < gap) continue;
        const p0 = { x: L.ring.x + Math.cos(a0) * L.ring.r, y: L.ring.y + Math.sin(a0) * L.ring.r };
        const p1 = { x: L.ring.x + Math.cos(a1) * L.ring.r, y: L.ring.y + Math.sin(a1) * L.ring.r };
        segs.push({ p0, p1, s: g.project((p0.x + p1.x) / 2, (p0.y + p1.y) / 2).s });
      }
      const centerS = g.project(L.ring.x, L.ring.y).s;
      const wallHeight = 30;
      g.lift = 2;
      segs.filter(s => s.s <= centerS).forEach(s => g.wall(s.p0.x, s.p0.y, s.p1.x, s.p1.y, wallHeight, wallTone, site ? 1 : .55));
      g.lift = g.base;

      // Links along the request path; lit as far as a request actually gets.
      const pathPts = [null, L.ownership, L.routing, L.gateway, L.origin];
      const link = (a, b, lit, dashed) => {
        ctx.strokeStyle = lit ? P.brand : P.ink3;
        ctx.globalAlpha = lit ? .75 : .28;
        ctx.lineWidth = lit ? 1.6 : 1;
        if (dashed) ctx.setLineDash([4, 5]);
        g.beginPath(); g.moveTo(a.x, a.y); g.lineTo(b.x, b.y); g.stroke();
        ctx.setLineDash([]); ctx.globalAlpha = 1;
      };
      L.visitors.forEach(v => link(v, L.ownership, m.reach >= 1, !site));
      link(L.ownership, L.routing, m.reach >= 2, m.reach < 2);
      link(L.routing, L.gateway, m.reach >= 3, m.reach < 3);
      link(L.gateway, L.origin, m.reach >= 4, m.reach < 4);

      // Direct access to the origin that skirts the gateway, while it is unverified.
      if (site && !m.hop.origin.ok) {
        const from = L.visitors[4], via = { x: W * .44, y: H * .96 }, to = { x: L.ring.x, y: L.ring.y + L.ring.r * .55 };
        ctx.strokeStyle = P.bad; ctx.globalAlpha = .5; ctx.lineWidth = 1.2; ctx.setLineDash([3, 6]);
        g.beginPath(); g.moveTo(from.x, from.y); g.quadraticCurveTo(via.x, via.y, to.x, to.y); g.stroke();
        ctx.setLineDash([]); ctx.globalAlpha = 1;
        const q = g.project(via.x, via.y * .97);
        ctx.font = '500 9.5px "IBM Plex Mono", ui-monospace, monospace'; ctx.textAlign = "center"; ctx.textBaseline = "middle";
        ctx.fillStyle = P.bad; ctx.globalAlpha = .9; ctx.fillText("DIRECT ORIGIN ACCESS · NOT VERIFIED", q.x, q.y);
        ctx.globalAlpha = 1;
      }

      // Request packets. They travel only as far as the verified chain goes.
      if (m.reach > 0) {
        const count = 10;
        for (let k = 0; k < count; k++) {
          const share = k / count;
          const blocked = m.reach === 4 && share < m.blockedShare;
          const flagged = m.reach === 4 && !blocked && share < m.matchedShare + m.blockedShare;
          const stopAt = blocked ? 3 : m.reach;
          const u = ((moving ? clock * .12 : .42) + k / count + .013 * k) % 1;
          const s = u * (stopAt + .5);
          let x, y, z = g.base, alpha = 1, color = flagged ? P.warn : P.brand;
          const start = L.visitors[k % L.visitors.length];
          if (s <= stopAt) {
            const seg = Math.min(stopAt - 1, Math.floor(s)), f = s - seg;
            const a = seg === 0 ? start : pathPts[seg], b = seg === 0 ? pathPts[1] : pathPts[seg + 1];
            const from = seg === 0 ? start : a;
            x = from.x + (b.x - from.x) * f; y = from.y + (b.y - from.y) * f;
            z += Math.sin(f * Math.PI) * 10;
          } else {
            const end = pathPts[stopAt], fade = (s - stopAt) / .5;
            x = end.x; y = end.y; alpha = 1 - fade;
            color = stopAt === 4 ? P.ok : P.bad;
            const q = g.project(x, y);
            ctx.globalAlpha = alpha * .8; ctx.strokeStyle = color; ctx.lineWidth = 1.2;
            g.beginPath(); g.arc(x, y, 6 + fade * 20, 0, TAU); g.stroke();
            ctx.globalAlpha = 1;
            if (blocked) { x -= fade * 26; }
            void q;
          }
          const q = g.project(x, y, z);
          g.glow(q.x, q.y, 10 * q.s, color, .45 * alpha);
          ctx.globalAlpha = alpha; ctx.fillStyle = color;
          ctx.beginPath(); ctx.arc(q.x, q.y, 2.6 * q.s, 0, TAU); ctx.fill();
          ctx.globalAlpha = 1;
        }
      }

      // Checkpoints.
      hits = [];
      L.visitors.forEach((v, i) => g.ball(v.x, v.y, 3.8, site ? P.ink2 : P.ink3, { alpha: site ? .9 : .5, z: g.base + (i % 2) * 4 }));
      const nodes = [
        { key: "ownership", at: L.ownership, draw: tone => g.cube(L.ownership.x, L.ownership.y, 8, tone, { glow: site ? tone : null, glowA: .6 }) },
        { key: "routing", at: L.routing, draw: tone => g.ball(L.routing.x, L.routing.y, 5.5, tone, { glow: site ? tone : null, glowA: .5 }) },
        { key: "gateway", at: L.gateway, draw: tone => g.cube(L.gateway.x, L.gateway.y, 11, tone, { z: g.base + 8, glow: site ? tone : null, glowA: .8, ring: site ? tone : null }) },
        { key: "origin", at: L.origin, draw: tone => g.cube(L.origin.x, L.origin.y, 13, site ? P.ink2 : P.ink3, { z: g.base + 6, glow: m.reach === 4 ? P.ok : null, glowA: .7, ring: tone }) },
      ];
      nodes.forEach((n, i) => {
        const tone = n.key === "origin" ? (!site ? P.ink3 : m.hop.origin.ok ? P.ok : P.bad) : hopTone(i, n.key);
        if (hover === n.key) {
          g.lift = 0; ctx.globalAlpha = .18; ctx.fillStyle = P.brand;
          g.beginPath(); g.arc(n.at.x, n.at.y, 26, 0, TAU); g.fill();
          ctx.globalAlpha = 1; g.lift = g.base;
        }
        n.draw(tone);
        const q = g.project(n.at.x, n.at.y, g.base + 10);
        hits.push({ key: n.key, x: q.x, y: q.y, tone });
      });

      // The near half of the wall stands in front of the gateway and origin.
      g.lift = 2;
      segs.filter(s => s.s > centerS).forEach(s => g.wall(s.p0.x, s.p0.y, s.p1.x, s.p1.y, wallHeight, wallTone, site ? 1 : .55));
      g.lift = g.base;

      // Labels face the reader.
      ctx.textAlign = "center"; ctx.textBaseline = "middle";
      hits.forEach(h => {
        const hop = HOPS.find(x => x.key === h.key), st = m.hop[h.key];
        // Neighbouring checkpoints alternate above and below, so their labels never share a line.
        const dy = { ownership: -40, routing: 26, gateway: -52, origin: 40 }[h.key];
        ctx.font = '500 9.5px "IBM Plex Mono", ui-monospace, monospace';
        ctx.fillStyle = hover === h.key ? P.ink : P.ink3;
        ctx.fillText(hop.name.toUpperCase(), h.x, h.y + dy);
        if (W >= 520) {
          ctx.font = '600 11.5px "IBM Plex Sans", system-ui, sans-serif';
          ctx.fillStyle = site ? (st.ok ? P.ok : h.tone === P.ink3 ? P.ink2 : h.tone) : P.ink3;
          const text = h.key === "gateway" ? `filtering ${model.mode || "unknown"}` : h.key === "routing" && st.ok ? "via gateway · verified" : st.text;
          ctx.fillText(text.length > 30 ? text.slice(0, 29) + "…" : text, h.x, h.y + dy + 14);
        }
      });
      const vq = g.project(L.visitors[2].x, L.visitors[2].y + 34);
      ctx.font = '500 9.5px "IBM Plex Mono", ui-monospace, monospace'; ctx.fillStyle = P.ink3;
      ctx.fillText("VISITORS", vq.x, vq.y);
      if (m.numbers && m.reach === 4) {
        const oq = g.project(L.origin.x, L.origin.y + L.ring.r + 18, 0);
        ctx.fillStyle = P.ink2;
        ctx.fillText(`${m.numbers.requests.toLocaleString()} requests · ${m.numbers.blocked.toLocaleString()} blocked`, oq.x, oq.y);
      }
    }

    /* ---------- loop and interaction ---------- */
    let timer = 0;
    function frame(now) {
      raf = 0;
      if (!figure.isConnected) { teardown(); return; }
      const dt = last ? Math.min(.05, (now - last) / 1000) : 0;
      last = now;
      const idle = !drag && now - touchedAt > 4000;
      if (!still()) {
        clock += dt;
        if (idle) yawTarget = -.2 + Math.sin(clock * .18) * .26;
      }
      const ease = drag ? .35 : .09;
      yaw += (yawTarget - yaw) * ease;
      tilt += (tiltTarget - tilt) * ease;
      draw();
      const settling = Math.abs(yawTarget - yaw) > .001 || Math.abs(tiltTarget - tilt) > .001;
      // Full frame rate while someone is steering it; the unattended sway runs
      // at ~30fps on a timer instead of redrawing on every display frame.
      if (visible && (drag || (settling && !idle))) raf = requestAnimationFrame(frame);
      else if (visible && (!still() || settling)) timer = setTimeout(() => { timer = 0; wake(); }, Math.max(0, 33 - (performance.now() - now)));
      else last = 0;
    }
    function wake() {
      if (timer) { clearTimeout(timer); timer = 0; }
      if (!raf) raf = requestAnimationFrame(frame);
    }
    function fit() {
      const rect = canvas.getBoundingClientRect();
      W = rect.width; H = rect.height;
      ratio = Math.min(2, window.devicePixelRatio || 1);
      canvas.width = Math.max(1, Math.round(W * ratio));
      canvas.height = Math.max(1, Math.round(H * ratio));
      wake();
    }
    function hitAt(ev) {
      const r = canvas.getBoundingClientRect(), x = ev.clientX - r.left, y = ev.clientY - r.top;
      let best = null, bestD = 30;
      hits.forEach(h => { const d = Math.hypot(h.x - x, h.y - y); if (d < bestD) { bestD = d; best = h; } });
      return best;
    }
    function showTip(h) {
      if (!h) { tip.hidden = true; return; }
      const hop = HOPS.find(x => x.key === h.key), st = model.hop[h.key];
      tip.innerHTML = `<b>${esc(hop.name)}</b><span>${esc(site ? st.text : "waiting for a website")}</span><small>${esc(hop.role)} · click to ${site ? "open" : "add a website"}</small>`;
      tip.hidden = false;
      const maxX = W - tip.offsetWidth - 8;
      tip.style.left = `${clamp(h.x - tip.offsetWidth / 2, 8, Math.max(8, maxX))}px`;
      tip.style.top = `${Math.max(8, h.y - tip.offsetHeight - 58)}px`;
    }
    canvas.addEventListener("pointerdown", ev => {
      drag = { x: ev.clientX, y: ev.clientY, moved: 0, yaw: yawTarget, tilt: tiltTarget };
      canvas.setPointerCapture(ev.pointerId);
      touchedAt = performance.now();
      wake();
    });
    canvas.addEventListener("pointermove", ev => {
      if (drag) {
        const dx = ev.clientX - drag.x, dy = ev.clientY - drag.y;
        drag.moved = Math.max(drag.moved, Math.hypot(dx, dy));
        yawTarget = clamp(drag.yaw + dx * .006, -.6, .6);
        tiltTarget = clamp(drag.tilt + dy * .004, .55, 1.05);
        touchedAt = performance.now();
        tip.hidden = true;
        canvas.style.cursor = "grabbing";
        wake();
        return;
      }
      const h = hitAt(ev);
      canvas.style.cursor = h ? "pointer" : "grab";
      if ((h?.key || null) !== hover) { hover = h?.key || null; wake(); }
      showTip(h);
    });
    canvas.addEventListener("pointerup", ev => {
      const wasClick = drag && drag.moved < 5;
      drag = null;
      canvas.style.cursor = "grab";
      if (wasClick) { const h = hitAt(ev); if (h) pick(h.key); }
      wake();
    });
    canvas.addEventListener("pointerleave", () => { if (!drag) { hover = null; tip.hidden = true; wake(); } });
    canvas.addEventListener("dblclick", () => { yawTarget = -.2; tiltTarget = .82; touchedAt = -1e9; wake(); });
    canvas.addEventListener("keydown", ev => {
      const step = { ArrowLeft: [-.12, 0], ArrowRight: [.12, 0], ArrowUp: [0, -.06], ArrowDown: [0, .06] }[ev.key];
      if (!step) return;
      ev.preventDefault();
      yawTarget = clamp(yawTarget + step[0], -.6, .6);
      tiltTarget = clamp(tiltTarget + step[1], .55, 1.05);
      touchedAt = performance.now();
      wake();
    });
    legend.addEventListener("click", ev => { const b = ev.target.closest("[data-hop]"); if (b) pick(b.dataset.hop); });
    legend.addEventListener("pointerover", ev => { const b = ev.target.closest("[data-hop]"); const key = b?.dataset.hop || null; if (key !== hover) { hover = key; wake(); } });
    legend.addEventListener("pointerleave", () => { hover = null; wake(); });
    if (!site && preview) preview.addEventListener("input", refresh);

    const ro = new ResizeObserver(fit); ro.observe(canvas);
    const io = new IntersectionObserver(entries => { visible = entries.some(e => e.isIntersecting); if (visible) wake(); }); io.observe(canvas);
    const themeWatch = new MutationObserver(() => { P = palette(); wake(); });
    themeWatch.observe(document.documentElement, { attributeFilter: ["data-theme"] });
    const motionWatch = new MutationObserver(wake);
    motionWatch.observe(document.body, { attributeFilter: ["data-motion"] });
    function teardown() { ro.disconnect(); io.disconnect(); themeWatch.disconnect(); motionWatch.disconnect(); }
    canvas.style.cursor = "grab";
    refresh();
    fit();
    return { refresh };
  }

  window.airlockGatewayScene = { mount };
})();
