(() => {
  "use strict";
  /* ==========================================================================
     Oops — the page for an address that leads nowhere.

     "404" is drawn from a few hundred particles that fly in and settle into
     the digits. They drift apart around the pointer, a scan line passes over
     them, the digits glitch every few seconds, and a probe runs at them and
     bursts: the route it looked for is not there. Beside it, the failed
     address, the closest real pages, and a short resolution log.

     Used by the console (mounted into #view for an unknown hash route) and by
     the site-wide 404 page (auto-mounts into #oopsRoot). Reduced motion and
     the product-wide pause preference hold a settled, static frame.
     ========================================================================== */

  const reduced = matchMedia("(prefers-reduced-motion: reduce)");
  const still = () => reduced.matches || document.body.dataset.motion === "paused" || document.hidden;
  const esc = s => String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/"/g, "&quot;");

  function lev(a, b) {
    a = a.toLowerCase(); b = b.toLowerCase();
    if (!a.length) return b.length;
    if (!b.length) return a.length;
    let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
    for (let i = 1; i <= a.length; i++) {
      const cur = [i];
      for (let j = 1; j <= b.length; j++) cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      prev = cur;
    }
    return prev[b.length];
  }
  /* The closest candidates to what was typed, by edit distance to any word of
     their key; substring matches are favoured. Nothing far away is offered. */
  function closest(query, candidates, n = 3) {
    const q = String(query || "").toLowerCase().replace(/^[#/]+/, "").replace(/\.html?$/, "").replace(/[-_/.]+/g, " ").trim();
    if (!q) return [];
    return candidates.map(c => {
      const key = String(c.key || c.label || "").toLowerCase();
      const words = key.replace(/[-_/.]+/g, " ").split(/\s+/).filter(Boolean);
      let score = Math.min(lev(q, key), ...words.map(w => lev(q, w)), ...q.split(" ").flatMap(part => words.map(w => lev(part, w) + 1)));
      if (words.some(w => w.length > 2 && (q.includes(w) || w.includes(q)))) score -= 2;
      return { ...c, score };
    // Tight on purpose: a suggestion that has nothing to do with what was typed is worse than none.
    }).filter(c => c.score <= Math.min(4, Math.max(2, Math.ceil(q.length * .3))))
      .sort((a, b) => a.score - b.score).slice(0, n);
  }

  function seeded(seed) {
    let s = seed >>> 0;
    return () => {
      s = (s + 0x6D2B79F5) >>> 0;
      let t = s;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  function stage(root) {
    const canvas = root.querySelector(".oopsStage canvas");
    const ctx = canvas.getContext("2d");
    let W = 0, H = 0, ratio = 1, parts = [], raf = 0, last = 0, t = 0, visible = true, dot = 2.3;
    const mouse = { x: -1e4, y: -1e4 };
    const palette = () => {
      const s = getComputedStyle(root), v = (name, fallback) => s.getPropertyValue(name).trim() || fallback;
      return { a: v("--oops-a", "#9D90FF"), b: v("--oops-b", "#E46E62"), text: v("--oops-text", "#E9EDF4"), dim: v("--oops-dim", "#8A94A6") };
    };
    let P = palette();

    let camX = .12, camY = -.32;
    /* The digits are a solid slab: a front and a back face of particles, with a
       middle layer along the outline so the sides read as solid when it turns. */
    function build() {
      const off = document.createElement("canvas");
      off.width = Math.max(1, Math.round(W)); off.height = Math.max(1, Math.round(H));
      const o = off.getContext("2d");
      // Large, dense digits: the particles have to read as "404" from across a wide stage.
      const size = Math.min(W * .42, H * .7);
      o.font = `800 ${size}px "Archivo", "Arial Black", "Helvetica Neue", sans-serif`;
      o.textAlign = "center"; o.textBaseline = "middle"; o.fillStyle = "#fff";
      o.fillText("404", W / 2, H * .46);
      const data = o.getImageData(0, 0, off.width, off.height).data;
      const step = Math.max(5, Math.round(size / 30));
      dot = Math.max(2.2, step * .55);
      const depth = size * .11;
      const on = (x, y) => x >= 0 && y >= 0 && x < off.width && y < off.height && data[(y * off.width + x) * 4 + 3] > 128;
      const homes = [];
      for (let y = 0; y < off.height; y += step) {
        for (let x = 0; x < off.width; x += step) {
          if (!on(x, y)) continue;
          homes.push({ x, y, z: -depth }, { x, y, z: depth });
          if (!on(x - step, y) || !on(x + step, y) || !on(x, y - step) || !on(x, y + step)) {
            homes.push({ x, y, z: -depth / 3, rim: true }, { x, y, z: depth / 3, rim: true });
          }
        }
      }
      const random = seeded(404);
      parts = homes.map((home, i) => {
        const old = parts[i];
        return { tx: home.x, ty: home.y, tz: home.z, rim: Boolean(home.rim), x: old ? old.x : random() * W, y: old ? old.y : random() * H,
          ph: random() * 6.283, hot: random() < .09, f: 1, depth: 0 };
      });
      place(0, still());
    }

    /* Turn the slab and project it in perspective. Each particle eases toward
       its projected spot, so the digits assemble, then keep their depth as they sway. */
    function place(dt, snap) {
      const cx = W / 2, cy = H * .46, F = Math.max(W, H) * 1.35;
      const moving = !still();
      const mx0 = mouse.x > -1e3 ? mouse.x / W - .5 : 0, my0 = mouse.y > -1e3 ? .5 - mouse.y / H : 0;
      const wantY = (moving ? Math.sin(t * .5) * .5 : -.34) + mx0 * .7;
      const wantX = (moving ? Math.sin(t * .37) * .16 : .14) + my0 * .4;
      const ease = snap ? 1 : Math.min(1, dt * 2.4);
      camY += (wantY - camY) * ease; camX += (wantX - camX) * ease;
      const cyw = Math.cos(camY), syw = Math.sin(camY), cxw = Math.cos(camX), sxw = Math.sin(camX);
      const glide = snap ? 1 : Math.min(1, dt * 3.2);
      for (const p of parts) {
        const X = p.tx - cx, Y = p.ty - cy, Z = p.tz;
        const X1 = X * cyw + Z * syw, Z1 = -X * syw + Z * cyw;
        const Y1 = Y * cxw - Z1 * sxw, Z2 = Y * sxw + Z1 * cxw;
        const f = F / (F + Z2);
        let gx = cx + X1 * f, gy = cy + Y1 * f;
        if (moving) {
          gx += Math.sin(t * 1.3 + p.ph) * 1.1; gy += Math.cos(t * 1.1 + p.ph) * 1.1;
          const mx = gx - mouse.x, my = gy - mouse.y, md = Math.hypot(mx, my);
          if (md < 80) { const push = (1 - md / 80) * 22; gx += mx / (md || 1) * push; gy += my / (md || 1) * push; }
        }
        p.x += (gx - p.x) * glide; p.y += (gy - p.y) * glide;
        p.f = f; p.depth = Z2;
      }
    }

    function draw(dt) {
      const moving = !still();
      if (moving) t += dt;
      place(dt, !moving);
      ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
      ctx.clearRect(0, 0, W, H);
      const cycle = t % 3.6, glitch = moving && cycle > 3.08 && cycle < 3.3;
      const beamY = ((t * .2) % 1) * H;
      const cx = W / 2, cy = H * .46;

      // A soft shadow on the floor beneath the slab.
      ctx.save();
      ctx.translate(cx, H * .84); ctx.scale(1, .16);
      const shadow = ctx.createRadialGradient(0, 0, 0, 0, 0, W * .34);
      shadow.addColorStop(0, "rgba(0,0,0,.55)"); shadow.addColorStop(1, "rgba(0,0,0,0)");
      ctx.fillStyle = shadow; ctx.fillRect(-W * .4, -W * .4, W * .8, W * .8);
      ctx.restore();

      if (moving) {
        ctx.globalAlpha = .22; ctx.fillStyle = P.a; ctx.fillRect(0, beamY, W, 1);
        ctx.globalAlpha = .06; ctx.fillRect(0, beamY - 18, W, 36);
      }

      // The probe: out from the left edge, straight at the digits, then a burst.
      const pk = (t % 4.4) / 4.4;
      if (moving && pk < .5) {
        const k = pk / .5, e = 1 - Math.pow(1 - k, 3);
        const sx = -10, ex = cx - Math.min(W * .2, 120);
        const px = sx + (ex - sx) * e, py = cy + Math.sin(k * Math.PI) * -H * .08;
        ctx.globalAlpha = .9; ctx.fillStyle = P.a;
        ctx.beginPath(); ctx.arc(px, py, 3, 0, Math.PI * 2); ctx.fill();
        for (let i = 1; i < 6; i++) {
          const bk = Math.max(0, e - i * .025);
          ctx.globalAlpha = .5 / i;
          ctx.beginPath(); ctx.arc(sx + (ex - sx) * bk, cy + Math.sin((bk / 1) * Math.PI) * -H * .08, 2.4, 0, Math.PI * 2); ctx.fill();
        }
      } else if (moving && pk < .78) {
        const k = (pk - .5) / .28, ex = cx - Math.min(W * .2, 120);
        ctx.globalAlpha = .7 * (1 - k); ctx.strokeStyle = P.b; ctx.lineWidth = 1.6;
        ctx.beginPath(); ctx.arc(ex, cy, 6 + k * 46, 0, Math.PI * 2); ctx.stroke();
        ctx.globalAlpha = (1 - k);
        ctx.font = '500 10px "IBM Plex Mono", ui-monospace, monospace'; ctx.fillStyle = P.b; ctx.textAlign = "center";
        ctx.fillText("NO ROUTE", ex, cy - 60 - k * 8);
      }

      // Far particles first, so the near face sits over the back face.
      const order = parts.slice().sort((a, b) => b.depth - a.depth);
      for (const p of order) {
        let x = p.x;
        if (glitch && Math.floor(p.ty / 16) % 3 === 1) x += 9 * Math.sin(p.ty * .7 + t * 40);
        const near = moving ? Math.max(0, 1 - Math.abs(p.y - beamY) / 22) : 0;
        const shade = Math.min(1, Math.max(.28, .42 + (p.f - .9) * 2.8));
        ctx.globalAlpha = Math.min(1, (p.rim ? .55 : .85) * shade + near * .3);
        ctx.fillStyle = p.hot ? P.a : P.text;
        const s = (p.rim ? dot * .8 : dot) * p.f + near * 1.2;
        ctx.fillRect(x - s / 2, p.y - s / 2, s, s);
        if (glitch && p.hot) { ctx.globalAlpha = .85; ctx.fillStyle = P.b; ctx.fillRect(x + 3, p.y - 1, 2.3, 2.3); }
      }
      ctx.globalAlpha = 1;
    }

    function frame(now) {
      raf = 0;
      if (!root.isConnected) { teardown(); return; }
      const dt = last ? Math.min(.05, (now - last) / 1000) : 0;
      last = now;
      if (W) draw(dt);
      if (visible && !still()) raf = requestAnimationFrame(frame);
      else last = 0;
    }
    const wake = () => { if (!raf) raf = requestAnimationFrame(frame); };
    function fit() {
      const rect = canvas.getBoundingClientRect();
      W = rect.width; H = rect.height;
      ratio = Math.min(2, window.devicePixelRatio || 1);
      canvas.width = Math.max(1, Math.round(W * ratio));
      canvas.height = Math.max(1, Math.round(H * ratio));
      if (!W || !H) return;
      build();
      wake();
    }
    const host = root.querySelector(".oopsStage");
    host.addEventListener("pointermove", ev => {
      const r = canvas.getBoundingClientRect();
      mouse.x = ev.clientX - r.left; mouse.y = ev.clientY - r.top;
    }, { passive: true });
    host.addEventListener("pointerleave", () => { mouse.x = mouse.y = -1e4; });
    const ro = new ResizeObserver(fit); ro.observe(canvas);
    const io = new IntersectionObserver(entries => { visible = entries.some(e => e.isIntersecting); if (visible) wake(); }); io.observe(canvas);
    const themeWatch = new MutationObserver(() => { P = palette(); wake(); });
    themeWatch.observe(document.documentElement, { attributeFilter: ["data-theme"] });
    const motionWatch = new MutationObserver(wake);
    motionWatch.observe(document.body, { attributeFilter: ["data-motion"] });
    reduced.addEventListener("change", fit);
    document.fonts?.ready.then(() => { if (root.isConnected) fit(); });
    function teardown() { ro.disconnect(); io.disconnect(); themeWatch.disconnect(); motionWatch.disconnect(); reduced.removeEventListener("change", fit); }
    fit();
  }

  /* A short log of the lookup, typed once. */
  function typeLog(el, lines) {
    const render = upto => {
      el.replaceChildren(...lines.slice(0, upto.line + 1).map((line, i) => {
        const div = document.createElement("div");
        div.className = line.kind;
        div.textContent = i === upto.line ? line.text.slice(0, upto.char) : line.text;
        if (i === upto.line) { const cur = document.createElement("span"); cur.className = "cur"; div.append(cur); }
        return div;
      }));
    };
    if (reduced.matches) { render({ line: lines.length - 1, char: lines[lines.length - 1].text.length }); return; }
    let line = 0, char = 0;
    const tick = () => {
      if (!el.isConnected) return;
      render({ line, char });
      if (char < lines[line].text.length) { char += 2; setTimeout(tick, 16); }
      else if (line < lines.length - 1) { line++; char = 0; setTimeout(tick, 320); }
    };
    setTimeout(tick, 500);
  }

  function mount(host, { path = location.pathname + location.hash, suggestions = [], actions = [], routes = 0 } = {}) {
    host.innerHTML = `<section class="oops" aria-labelledby="oopsTitle">
      <div class="oopsStage" aria-hidden="true"><canvas></canvas><span class="oopsSignal">signal lost · no route</span></div>
      <div class="oopsCopy">
        <span class="oopsEyebrow">Error 404 · page not found</span>
        <h1 id="oopsTitle"><span class="oopsWord" data-text="Oops.">Oops.</span> This address leads nowhere.</h1>
        <p>Nothing lives at <code>${esc(path)}</code>. It may have been mistyped, moved, or never existed.</p>
        ${suggestions.length ? `<nav class="oopsSuggest" aria-label="Closest pages"><span>Did you mean</span>
          ${suggestions.map(s => `<a href="${esc(s.href)}">${esc(s.label)}${s.hint ? `<small>${esc(s.hint)}</small>` : ""}</a>`).join("")}</nav>` : ""}
        <div class="oopsActions">${actions.map(a => a.href
          ? `<a class="oopsBtn${a.primary ? " pri" : ""}" href="${esc(a.href)}">${esc(a.label)}</a>`
          : `<button class="oopsBtn${a.primary ? " pri" : ""}" type="button" data-oops-action="${esc(a.id)}">${esc(a.label)}</button>`).join("")}</div>
        <div class="oopsTerm" aria-hidden="true"></div>
      </div></section>`;
    const root = host.querySelector(".oops");
    typeLog(root.querySelector(".oopsTerm"), [
      { kind: "c", text: `resolve ${path}` },
      { kind: "i", text: routes ? `searching ${routes} known routes` : "searching known routes" },
      { kind: "x", text: "no route matches · 404" },
      { kind: "i", text: suggestions.length ? `closest: ${suggestions.map(s => s.label).join(", ")}` : "nothing close enough to suggest" },
    ]);
    stage(root);
    return root;
  }

  window.airlockOops = { mount, closest };

  // The site-wide 404 page mounts itself.
  const standalone = document.getElementById("oopsRoot");
  if (standalone) {
    const PUBLIC = [
      ["/", "Home", "The platform"], ["/security", "Security", "Buyer security FAQ"], ["/pricing", "Pricing", "Plans and pilots"],
      ["/pilot", "Pilot", "Scope an engagement"], ["/support", "Support", "Contact"], ["/data-boundary", "Data boundary", "What leaves"],
      ["/airlock-deployment", "Deployment", "Deployment guide"], ["/dpa", "DPA", "Data processing"], ["/privacy", "Privacy", "Privacy policy"],
      ["/terms", "Terms", "Terms of service"], ["/trust-passport-demo", "Trust Passport", "What a passport contains"],
      ["/enterprise-admin", "Enterprise admin", "How operations run"], ["/ui/", "Console", "Open the workspace"],
    ];
    const candidates = PUBLIC.map(([href, label, hint]) => ({ key: `${href.replace(/\//g, " ")} ${label}`, href, label, hint }));
    mount(standalone, {
      path: location.pathname + location.search,
      suggestions: closest(location.pathname, candidates, 3),
      routes: PUBLIC.length,
      actions: [{ label: "Back to home", href: "/", primary: true }, { label: "Open console", href: "/ui/" }],
    });
  }
})();
