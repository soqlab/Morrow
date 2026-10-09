(() => {
  "use strict";
  /* ==========================================================================
     Airlock 3D charts.

     The console's chart helpers (barChart, donut, areaChart, gauge, radarChart,
     forceGraph) wrap their flat markup in <div class="c3d" data-c3d="type"
     data-c3d-cfg="{…}">. This module finds those blocks wherever they appear
     — a view, a drawer, a live refresh — and replaces the picture with a 3D
     chart on a perspective floor (space3d.js):

       bar     extruded columns, value on top, category on the floor
       donut   an extruded ring; the hovered slice lifts out
       area    a ribbon standing on the floor, with its axis ticks behind it
       gauge   an arch whose lit segments show the value
       radar   pillars at each axis, joined by a translucent roof
       graph   the crypto risk map, nodes raised by risk
       timeline  yearly columns split by a translucent Q-Day wall (HNDL exposure)
       curves  one probability ribbon per algorithm, cut by the same Q-Day wall

     Drag to turn, hover for exact values. Charts grow in once and then redraw
     only when someone interacts, so a page full of them costs nothing at rest.
     The flat markup stays in the block, visually hidden, for assistive
     technology; without canvas or the space kit the flat chart is left as is.
     Every number drawn comes from the cfg the helper built from real data.
     ========================================================================== */

  const TAU = Math.PI * 2;
  const reduced = matchMedia("(prefers-reduced-motion: reduce)");
  const still = () => reduced.matches || document.body.dataset.motion === "paused" || document.hidden;
  const clamp = (v, a, b) => Math.min(b, Math.max(a, v));
  const easeOut = k => 1 - Math.pow(1 - k, 3);
  const esc = s => String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/"/g, "&quot;");
  const short = (s, n) => (String(s).length > n ? String(s).slice(0, n - 1) + "…" : String(s));

  /* Colours are drawn every frame, so a var() is resolved once per chart and
     remembered until the theme changes; getComputedStyle inside the draw loop
     forces a style pass on every frame of an interaction. */
  const resolved = new WeakMap();
  function resolve(el, color, fallback) {
    const s = String(color || "").trim();
    const m = /^var\((--[\w-]+)(?:\s*,\s*(.+))?\)$/.exec(s);
    if (!m) return s || fallback;
    let memo = resolved.get(el);
    if (!memo) resolved.set(el, memo = new Map());
    const key = s + "|" + fallback;
    let out = memo.get(key);
    if (out === undefined) {
      out = getComputedStyle(el).getPropertyValue(m[1]).trim() || (m[2] ? resolve(el, m[2], fallback) : fallback);
      memo.set(key, out);
    }
    return out;
  }
  function palette(el) {
    const s = getComputedStyle(el), v = (name, fallback) => s.getPropertyValue(name).trim() || fallback;
    return {
      ink: v("--ink", "#E9EDF4"), ink2: v("--ink2", "#B8C0CC"), ink3: v("--ink3", "#8A94A6"), line: v("--line", "#1A2130"),
      ground: v("--surface", "#0A0E15"), track: v("--surface3", "#131925"), brand: v("--brand", "#7B6BFF"),
      ok: v("--ok", "#4FB58B"), warn: v("--warn", "#D4913F"), bad: v("--bad", "#E46E62"), info: v("--info", "#7B6BFF"),
    };
  }
  const tint = (color, a) => window.airlockSpace?.tint(color, a) || color;

  /* ---------- solid geometry on a space view ---------- */
  function path(ctx, q) { ctx.beginPath(); q.forEach((p, i) => (i ? ctx.lineTo(p.x, p.y) : ctx.moveTo(p.x, p.y))); ctx.closePath(); }
  function poly(g, pts, fill, shade) {
    const ctx = g.screen, q = pts.map(p => g.project(p[0], p[1], p[2]));
    path(ctx, q);
    ctx.fillStyle = fill; ctx.fill();
    if (shade) { ctx.fillStyle = shade; ctx.fill(); }
    return q;
  }
  /* Extrude a floor polygon between two heights, sides far to near, then the top. */
  function prism(g, base, z0, z1, fill, { top = "rgba(255,255,255,.12)", edge = null } = {}) {
    const n = base.length, faces = [];
    for (let i = 0; i < n; i++) {
      const a = base[i], b = base[(i + 1) % n];
      const mid = g.project((a[0] + b[0]) / 2, (a[1] + b[1]) / 2, (z0 + z1) / 2);
      faces.push({ pts: [[a[0], a[1], z0], [b[0], b[1], z0], [b[0], b[1], z1], [a[0], a[1], z1]], s: mid.s, shade: `rgba(0,0,0,${.22 + .16 * (i % 2)})` });
    }
    faces.sort((p, q) => p.s - q.s).forEach(f => poly(g, f.pts, fill, f.shade));
    const q = poly(g, base.map(p => [p[0], p[1], z1]), fill, top);
    if (edge) { g.screen.strokeStyle = edge; g.screen.lineWidth = 1; path(g.screen, q); g.screen.stroke(); }
    return q;
  }
  const AXIS_FONT = '500 10px "IBM Plex Mono", ui-monospace, monospace';
  function text(ctx, str, x, y, { font = AXIS_FONT, color, align = "center" } = {}) {
    setFont(ctx, font); ctx.fillStyle = color; ctx.textAlign = align; ctx.textBaseline = "middle";
    ctx.fillText(str, x, y);
  }
  /* ctx.font re-parses its string on every assignment; skip identical ones.
     draw() clears the remembered value, since resizing a canvas resets it. */
  function setFont(ctx, font) {
    if (ctx.__c3dFont !== font) { ctx.font = font; ctx.__c3dFont = font; }
  }
  /* Centred labels drawn in order; each one steps down past any label it would
     cover. Optional labels that still collide after a few steps are skipped,
     so earlier (more important) labels always win. */
  function labelsNoOverlap(ctx, items) {
    const placed = [], lineH = 15;
    for (const it of items) {
      setFont(ctx, it.font);
      const half = ctx.measureText(it.text).width / 2 + 3;
      let y = it.y, tries = 0;
      const hit = () => placed.some(p => it.x - half < p.x1 && it.x + half > p.x0 && y - lineH / 2 < p.y1 && y + lineH / 2 > p.y0);
      while (hit() && tries < (it.optional ? 2 : 6)) { y += lineH; tries++; }
      if (hit()) continue;
      placed.push({ x0: it.x - half, x1: it.x + half, y0: y - lineH / 2, y1: y + lineH / 2 });
      text(ctx, it.text, it.x, y, { font: it.font, color: it.color });
    }
  }

  /* ---------- chart specs ---------- */
  const SPECS = {
    bar(wrap, cfg) {
      const items = (cfg.items || []).filter(i => Number.isFinite(i.v));
      if (!items.length) return null;
      const n = items.length, max = Math.max(...items.map(i => i.v), 1);
      return {
        height: clamp(170 + n * 9, 200, 280), fitHeight: .62,
        label: `Bar chart: ${items.map(i => `${i.k} ${i.f}`).join(", ")}`,
        draw(g, ctx, { W, H, P, grow, hover }) {
          const top = H * .62, slot = W * .86 / n, side = Math.min(slot * .28, H * .12, 24), y = H * .52;
          const cols = items.map((it, i) => ({ it, i, x: W * .07 + slot * (i + .5), color: resolve(wrap, it.c, P.brand) }));
          cols.forEach(c => { c.s = g.project(c.x, y, 0).s; });
          const hits = [];
          for (const c of [...cols].sort((a, b) => a.s - b.s)) {
            const on = hover === c.i, hgt = Math.max(2, c.it.v / max * top * grow), z0 = on ? 6 : 0;
            g.lift = 0; g.screen.fillStyle = "rgba(0,0,0,.28)";
            g.beginPath(); g.ellipse(c.x + side * .35, y + side * .35, side * 1.25, side * 1.25, 0, 0, TAU); g.fill();
            prism(g, [[c.x - side, y - side], [c.x + side, y - side], [c.x + side, y + side], [c.x - side, y + side]], z0, z0 + hgt, c.color,
              { top: on ? "rgba(255,255,255,.32)" : "rgba(255,255,255,.14)", edge: on ? P.ink : null });
            const q = g.project(c.x, y, z0 + hgt), foot = g.project(c.x, y + side + 16, 0);
            hits.push({ i: c.i, x: q.x, y: q.y, r: Math.max(22, slot * .45), tip: [c.it.k, c.it.f], q, foot });
          }
          const crowded = n > 6 || W / n < 70;
          hits.forEach(h => {
            const it = items[h.i], on = hover === h.i;
            if (grow > .98) text(ctx, it.f, h.q.x, h.q.y - 12, { font: `600 ${on ? 12 : 11}px "IBM Plex Mono", ui-monospace, monospace`, color: on ? P.ink : P.ink2 });
          });
          // Category names sit on the floor; the hovered one is placed first so it never gets pushed.
          labelsNoOverlap(ctx, [...hits]
            .sort((a, b) => (hover === b.i) - (hover === a.i) || a.foot.x - b.foot.x)
            .map(h => ({
              text: short(items[h.i].k, crowded ? 12 : 18), x: h.foot.x, y: h.foot.y,
              font: '500 10.5px "IBM Plex Sans", system-ui, sans-serif', color: hover === h.i ? P.ink : P.ink3,
            })));
          return hits;
        },
      };
    },

    donut(wrap, cfg) {
      const segs = (cfg.segs || []).filter(s => s.v > 0);
      const total = segs.reduce((a, s) => a + s.v, 0);
      if (!total) return null;
      return {
        height: 230, fitHeight: .2, yaw: -.15, tilt: .95,
        label: `Distribution: ${segs.map(s => `${s.k} ${s.v} (${s.p})`).join(", ")}`,
        legend: `<ul class="c3dLegend">${segs.map((s, i) => `<li data-i="${i}"><i style="background:${esc(s.c)}"></i><span>${esc(s.k)}</span><b>${esc(s.f ?? s.v)}</b><small>${esc(s.p)}</small></li>`).join("")}</ul>`,
        draw(g, ctx, { W, H, P, grow, hover }) {
          const cx = W * .5, cy = H * .5, R = Math.min(W * .34, H * .72), r = R * .56, zH = 18;
          let start = -Math.PI / 2;
          const slices = segs.map((s, i) => {
            const span = s.v / total * TAU * grow, a0 = start, a1 = start + span;
            start = a1;
            const mid = (a0 + a1) / 2, on = hover === i, push = on ? R * .08 : 0;
            const ox = Math.cos(mid) * push, oy = Math.sin(mid) * push;
            const steps = Math.max(2, Math.ceil(span / (TAU / 64)));
            const outer = [], inner = [];
            for (let k = 0; k <= steps; k++) {
              const a = a0 + span * k / steps;
              outer.push([cx + ox + Math.cos(a) * R, cy + oy + Math.sin(a) * R]);
              inner.push([cx + ox + Math.cos(a) * r, cy + oy + Math.sin(a) * r]);
            }
            const c = g.project(cx + ox + Math.cos(mid) * (R + r) / 2, cy + oy + Math.sin(mid) * (R + r) / 2, 0);
            return { i, s, base: outer.concat(inner.reverse()), z0: on ? 8 : 0, color: resolve(wrap, s.c, P.brand), depth: c.s, mid, ox, oy };
          });
          const hits = [];
          for (const sl of [...slices].sort((a, b) => a.depth - b.depth)) {
            if (sl.base.length < 6) continue;
            prism(g, sl.base, sl.z0, sl.z0 + zH, sl.color, { top: hover === sl.i ? "rgba(255,255,255,.3)" : "rgba(255,255,255,.12)" });
            const q = g.project(cx + sl.ox + Math.cos(sl.mid) * (R + r) / 2, cy + sl.oy + Math.sin(sl.mid) * (R + r) / 2, sl.z0 + zH);
            hits.push({ i: sl.i, x: q.x, y: q.y, r: 34, tip: [sl.s.k, `${sl.s.f ?? sl.s.v} · ${sl.s.p}`] });
          }
          const c = g.project(cx, cy, zH * .5);
          text(ctx, String(cfg.center ?? total), c.x, c.y - 4, { font: '700 22px "Archivo", "IBM Plex Sans", sans-serif', color: P.ink });
          if (cfg.sub) text(ctx, String(cfg.sub).toUpperCase(), c.x, c.y + 16, { font: '500 9.5px "IBM Plex Mono", ui-monospace, monospace', color: P.ink3 });
          return hits;
        },
      };
    },

    area(wrap, cfg) {
      const pts = (cfg.pts || []).filter(p => Number.isFinite(p.v));
      if (pts.length < 2) return null;
      const mn = Number(cfg.mn) || 0, mx = Number(cfg.mx) || Math.max(...pts.map(p => p.v)), sp = (mx - mn) || 1;
      const n = pts.length;
      return {
        // Seen more from the side than other charts, so height and its ticks stay readable.
        height: (Number(cfg.h) || 190) + 60, fitHeight: .95, yaw: -.18, tilt: .48,
        label: `${cfg.label || "Trend"}: ${pts.map(p => `${p.k} ${p.f}`).join(", ")}`,
        draw(g, ctx, { W, H, P, grow, hover }) {
          const color = resolve(wrap, cfg.color, P.brand);
          const x0 = W * .1, x1 = W * .96, yb = H * .52, D = H * .09, top = H * 1.1;
          const X = i => x0 + (x1 - x0) * i / (n - 1), Z = v => (v - mn) / sp * top * grow;
          const s = g.screen;
          // Axis ticks on a back plane; a label too close to the previous one is left out.
          let lastTickY = Infinity;
          (cfg.ticks || []).forEach(t => {
            const z = (t.v - mn) / sp * top;
            const a = g.project(x0, yb - D * 2.2, z), b = g.project(x1, yb - D * 2.2, z);
            s.strokeStyle = P.line; s.lineWidth = 1; s.beginPath(); s.moveTo(a.x, a.y); s.lineTo(b.x, b.y); s.stroke();
            if (Math.abs(lastTickY - a.y) >= 12) { text(s, t.lab, a.x - 8, a.y, { color: P.ink3, align: "right" }); lastTickY = a.y; }
          });
          const back = pts.map((p, i) => [X(i), yb - D, Z(p.v)]), front = pts.map((p, i) => [X(i), yb + D, Z(p.v)]);
          poly(g, [[x0, yb - D, 0], ...back, [x1, yb - D, 0]], tint(color, .1));
          for (let i = 0; i < n - 1; i++) poly(g, [back[i], back[i + 1], front[i + 1], front[i]], tint(color, .3));
          poly(g, [[x0, yb + D, 0], ...front, [x1, yb + D, 0]], tint(color, .2));
          const line = front.map(p => g.project(p[0], p[1], p[2]));
          s.strokeStyle = color; s.lineWidth = 2.2; s.lineJoin = "round";
          s.beginPath(); line.forEach((q, i) => (i ? s.lineTo(q.x, q.y) : s.moveTo(q.x, q.y))); s.stroke();
          const hits = [], step = Math.max(1, Math.round(n / 7));
          line.forEach((q, i) => {
            const on = hover === i;
            if (on) {
              const f = g.project(X(i), yb + D, 0);
              s.strokeStyle = tint(color, .6); s.lineWidth = 1; s.setLineDash([3, 3]);
              s.beginPath(); s.moveTo(f.x, f.y); s.lineTo(q.x, q.y); s.stroke(); s.setLineDash([]);
            }
            if (on || n <= 30) { s.fillStyle = color; s.beginPath(); s.arc(q.x, q.y, on ? 4.5 : 2.6, 0, TAU); s.fill(); }
            hits.push({ i, x: q.x, y: q.y, r: Math.max(16, (x1 - x0) / n * .6), tip: [pts[i].k, pts[i].f] });
            if (i % step === 0 || i === n - 1) {
              const f = g.project(X(i), yb + D * 2.6, 0);
              text(s, short(pts[i].k, 10), f.x, f.y, { color: on ? P.ink : P.ink3 });
            }
          });
          return hits;
        },
      };
    },

    gauge(wrap, cfg) {
      const frac = clamp(Number(cfg.frac) || 0, 0, 1);
      return {
        height: 190, fitHeight: .5, yaw: -.25, tilt: .7,
        label: `Gauge: ${cfg.text}${cfg.label ? ` ${cfg.label}` : ""}`,
        draw(g, ctx, { W, H, P, grow, hover }) {
          const col = resolve(wrap, cfg.col, P.ok), cx = W * .5, y = H * .56, R = Math.min(W * .3, H * .9), Rin = R * .76, D = 10, N = 40;
          const lit = frac * grow;
          const segs = [];
          for (let i = 0; i < N; i++) {
            const a0 = Math.PI - i / N * Math.PI, a1 = Math.PI - (i + 1) / N * Math.PI;
            const o0 = [cx + Math.cos(a0) * R, Math.sin(a0) * R], o1 = [cx + Math.cos(a1) * R, Math.sin(a1) * R];
            const i0 = [cx + Math.cos(a0) * Rin, Math.sin(a0) * Rin], i1 = [cx + Math.cos(a1) * Rin, Math.sin(a1) * Rin];
            const on = (i + .5) / N <= lit;
            segs.push({ o0, o1, i0, i1, fill: on ? col : P.track, on });
          }
          const s = g.screen;
          segs.forEach(sg => {
            poly(g, [[sg.o0[0], y - D, sg.o0[1]], [sg.o1[0], y - D, sg.o1[1]], [sg.o1[0], y + D, sg.o1[1]], [sg.o0[0], y + D, sg.o0[1]]], sg.fill, "rgba(255,255,255,.1)");
          });
          segs.forEach(sg => {
            poly(g, [[sg.o0[0], y + D, sg.o0[1]], [sg.o1[0], y + D, sg.o1[1]], [sg.i1[0], y + D, sg.i1[1]], [sg.i0[0], y + D, sg.i0[1]]], sg.fill, "rgba(0,0,0,.22)");
          });
          const c = g.project(cx, y + D, R * .22);
          text(s, String(cfg.text), c.x, c.y, { font: '700 26px "Archivo", "IBM Plex Sans", sans-serif', color: col });
          if (cfg.label) text(s, String(cfg.label).toUpperCase(), c.x, c.y + 22, { font: '500 9.5px "IBM Plex Mono", ui-monospace, monospace', color: P.ink3 });
          const tipAt = g.project(cx, y, R);
          void hover;
          return [{ i: 0, x: tipAt.x, y: tipAt.y + 20, r: R * .7, tip: [cfg.label || "Score", `${cfg.text} of ${cfg.max ?? 100}`] }];
        },
      };
    },

    radar(wrap, cfg) {
      const pts = (cfg.pts || []).slice(0, 7);
      if (pts.length < 3) return null;
      return {
        height: 300, fitHeight: .45, yaw: -.2,
        label: `Radar: ${pts.map(p => `${p.k} ${Math.round(p.v)}`).join(", ")}`,
        draw(g, ctx, { W, H, P, grow, hover }) {
          const cx = W * .5, cy = H * .5, R = Math.min(W * .3, H * .78), top = H * .45, n = pts.length, s = g.screen;
          const at = (i, f) => { const a = -Math.PI / 2 + i / n * TAU; return [cx + Math.cos(a) * R * f, cy + Math.sin(a) * R * f]; };
          const tone = v => (v >= 70 ? P.bad : v >= 45 ? P.warn : v >= 20 ? P.info : P.ink3);
          [.25, .5, .75, 1].forEach(f => {
            const q = pts.map((_, i) => { const p = at(i, f); return g.project(p[0], p[1], 0); });
            s.strokeStyle = P.line; s.lineWidth = f === 1 ? 1.4 : 1; path(s, q); s.stroke();
          });
          pts.forEach((_, i) => {
            const c = g.project(cx, cy, 0), e = at(i, 1), q = g.project(e[0], e[1], 0);
            s.strokeStyle = P.line; s.lineWidth = 1; s.beginPath(); s.moveTo(c.x, c.y); s.lineTo(q.x, q.y); s.stroke();
          });
          const tops = pts.map((p, i) => { const b = at(i, p.v / 100); return [b[0], b[1], p.v / 100 * top * grow]; });
          poly(g, tops.map(t => [t[0], t[1], 0]), tint(P.brand, .1));
          const order = tops.map((t, i) => ({ t, i, s: g.project(t[0], t[1], 0).s })).sort((a, b) => a.s - b.s);
          order.forEach(({ t, i }) => {
            const f = g.project(t[0], t[1], 0), q = g.project(t[0], t[1], t[2]);
            s.strokeStyle = tint(tone(pts[i].v), .8); s.lineWidth = hover === i ? 3 : 2;
            s.beginPath(); s.moveTo(f.x, f.y); s.lineTo(q.x, q.y); s.stroke();
          });
          const roof = poly(g, tops, tint(P.brand, .22));
          s.strokeStyle = P.brand; s.lineWidth = 1.6; path(s, roof); s.stroke();
          const hits = [];
          tops.forEach((t, i) => {
            const q = g.project(t[0], t[1], t[2]), on = hover === i;
            s.fillStyle = tone(pts[i].v); s.beginPath(); s.arc(q.x, q.y, on ? 5.5 : 3.8, 0, TAU); s.fill();
            const e = at(i, 1.2), l = g.project(e[0], e[1], 0);
            text(s, short(pts[i].k, 18), l.x, l.y - 6, { font: '500 10.5px "IBM Plex Sans", system-ui, sans-serif', color: on ? P.ink : P.ink2 });
            text(s, String(Math.round(pts[i].v)), l.x, l.y + 8, { font: '600 11px "IBM Plex Mono", ui-monospace, monospace', color: tone(pts[i].v) });
            hits.push({ i, x: q.x, y: q.y, r: 22, tip: [pts[i].k, `${Math.round(pts[i].v)} of 100`] });
          });
          return hits;
        },
      };
    },

    graph(wrap, cfg) {
      const nodes = (cfg.nodes || []).slice(0, 160);
      if (!nodes.length) return null;
      const byType = new Map();
      nodes.forEach(n => { if (!byType.has(n.type)) byType.set(n.type, []); byType.get(n.type).push(n); });
      const types = [...byType.keys()];
      const top = new Set(cfg.top || []);
      const peak = Math.max(0, ...nodes.map(n => n.risk));
      return {
        height: clamp(Number(cfg.h) || 400, 320, 500), fitHeight: .3, tilt: .78, yaw: -.18,
        label: `Relationship map of ${nodes.length} nodes; highest risk ${Math.round(peak)}`,
        draw(g, ctx, { W, H, P, grow, hover }) {
          const cx = W * .5, cy = H * .5, rx = W * .43, ry = H * .47, s = g.screen;
          const tone = v => (v >= 70 ? P.bad : v >= 45 ? P.warn : v >= 20 ? P.info : P.ink3);
          const pos = new Map();
          types.forEach((type, ti) => {
            const list = byType.get(type), a0 = ti / types.length * TAU + .08, a1 = (ti + 1) / types.length * TAU - .08;
            list.forEach((n, i) => {
              const a = list.length === 1 ? (a0 + a1) / 2 : a0 + (a1 - a0) * i / (list.length - 1);
              // Neighbours in a crowded sector alternate between three rings so their labels separate.
              const ring = 1 - (i % 3) * .24;
              pos.set(n.id, { x: cx + Math.cos(a) * rx * ring, y: cy + Math.sin(a) * ry * ring, z: (10 + n.risk * .55) * grow, n });
            });
          });
          const hotAt = Math.max(18, peak * .62);
          (cfg.edges || []).forEach(e => {
            const a = pos.get(e.s), b = pos.get(e.t);
            if (!a || !b) return;
            const hot = Math.max(a.n.risk, b.n.risk) >= hotAt && peak >= 18, lift = 30 * grow;
            const pts = [];
            for (let k = 0; k <= 14; k++) {
              const u = k / 14, v = 1 - u;
              const x = v * v * a.x + 2 * v * u * cx + u * u * b.x, y = v * v * a.y + 2 * v * u * cy + u * u * b.y;
              pts.push(g.project(x, y, v * a.z + u * b.z + Math.sin(u * Math.PI) * lift));
            }
            s.strokeStyle = hot ? tint(P.bad, .55) : tint(P.ink3, .22); s.lineWidth = hot ? 1.4 : 1;
            s.beginPath(); pts.forEach((q, i) => (i ? s.lineTo(q.x, q.y) : s.moveTo(q.x, q.y))); s.stroke();
          });
          const order = [...pos.values()].sort((a, b) => g.project(a.x, a.y, 0).s - g.project(b.x, b.y, 0).s);
          const hits = [], labels = [];
          order.forEach(p => {
            const on = hover === p.n.id;
            const q = g.ball(p.x, p.y, 3 + p.n.risk / 30 + (on ? 2 : 0), tone(p.n.risk), { z: p.z, glow: p.n.risk >= hotAt ? tone(p.n.risk) : null, glowA: .6, stroke: on ? P.ink : null });
            hits.push({ i: p.n.id, x: q.x, y: q.y, r: 12, tip: [p.n.label, `risk ${Math.round(p.n.risk)} · ${p.n.type}`] });
            if (top.has(p.n.id) || on) labels.push({
              text: short(p.n.label, 22), x: q.x, y: q.y - 12 - (3 + p.n.risk / 30), optional: !on, weight: on ? Infinity : p.n.risk,
              font: '500 10.5px "IBM Plex Sans", system-ui, sans-serif', color: on ? P.ink : P.ink2,
            });
          });
          // The riskiest nodes keep their names; a label with no room is left to the hover tooltip.
          labelsNoOverlap(s, labels.sort((a, b) => b.weight - a.weight));
          return hits;
        },
      };
    },

    /* Exposure accumulating year by year. Columns before the model's Q-Day are
       captured but sealed; from Q-Day on they are readable, and a translucent
       wall stands where that changes. Scale and ticks come from the page. */
    timeline(wrap, cfg) {
      const items = (cfg.items || []).filter(i => Number.isFinite(i.v));
      if (items.length < 2) return null;
      const n = items.length, max = Math.max(Number(cfg.max) || 0, ...items.map(i => i.v), 1);
      const qi = Number.isInteger(cfg.qIndex) && cfg.qIndex > 0 && cfg.qIndex < n ? cfg.qIndex : -1;
      const peak = items.reduce((m, it, i) => (it.v > items[m].v ? i : m), 0);
      return {
        height: 290, fitHeight: .72, yaw: -.24, tilt: .72,
        label: `Modelled exposure by year: ${items.map(i => `${i.k} ${i.f}`).join(", ")}${qi > 0 ? `; model Q-Day ${cfg.qYear}` : ""}`,
        legend: `<ul class="c3dLegend c3dLegendWide"><li><i style="background:${esc(cfg.before)};opacity:.65"></i><span>Captured, still sealed</span></li><li><i style="background:${esc(cfg.after)}"></i><span>Readable after model Q-Day</span></li></ul>`,
        draw(g, ctx, { W, H, P, grow, hover }) {
          const x0 = W * .1, x1 = W * .97, slot = (x1 - x0) / n, side = clamp(slot * .3, 3, 15), y = H * .56, top = H * .78, s = g.screen;
          const before = resolve(wrap, cfg.before, P.warn), after = resolve(wrap, cfg.after, P.bad);
          const X = i => x0 + slot * (i + .5), yw = y - side * 3.2;
          // Value ticks on a back plane.
          (cfg.ticks || []).forEach(t => {
            const z = t.v / max * top, a = g.project(x0, yw, z), b = g.project(x1, yw, z);
            s.strokeStyle = P.line; s.lineWidth = 1; s.beginPath(); s.moveTo(a.x, a.y); s.lineTo(b.x, b.y); s.stroke();
            text(s, t.lab, a.x - 8, a.y, { color: P.ink3, align: "right" });
          });
          if (qi > 0) {
            const xq = x0 + slot * qi, far = yw, near = y + side * 4;
            // Seen from the front the wall is nearly edge-on, so the readable years also get a shaded floor.
            poly(g, [[xq, far, 0], [x1, far, 0], [x1, near, 0], [xq, near, 0]], tint(after, .1));
            const wall = poly(g, [[xq, far, 0], [xq, near, 0], [xq, near, top * 1.06], [xq, far, top * 1.06]], tint(after, .1));
            s.strokeStyle = tint(after, .55); s.lineWidth = 1; path(s, wall); s.stroke();
            const l = g.project(xq, far, top * 1.1);
            text(s, `MODEL Q-DAY ${cfg.qYear}`, l.x + 6, l.y, { color: after, align: "left", font: '600 10px "IBM Plex Mono", ui-monospace, monospace' });
          }
          const cols = items.map((it, i) => ({ it, i, x: X(i), after: qi > 0 && i >= qi, s: g.project(X(i), y, 0).s }));
          const hits = [];
          for (const c of cols.sort((a, b) => a.s - b.s)) {
            const on = hover === c.i, hgt = Math.max(1.5, c.it.v / max * top * grow), z0 = on ? 5 : 0;
            prism(g, [[c.x - side, y - side], [c.x + side, y - side], [c.x + side, y + side], [c.x - side, y + side]], z0, z0 + hgt,
              c.after ? after : tint(before, .72), { top: on ? "rgba(255,255,255,.34)" : "rgba(255,255,255,.14)", edge: on ? P.ink : null });
            const q = g.project(c.x, y, z0 + hgt), foot = g.project(c.x, y + side + 14, 0);
            hits.push({ i: c.i, x: q.x, y: q.y, r: Math.max(14, slot * .55), q, foot,
              tip: [c.it.k, `${c.it.f} · ${c.after ? "readable after model Q-Day" : "captured, still sealed"}`] });
          }
          if (grow > .98) hits.forEach(h => {
            if (h.i === peak || h.i === n - 1 || hover === h.i) {
              text(ctx, items[h.i].f, h.q.x, h.q.y - 11, { font: `600 ${hover === h.i ? 12 : 11}px "IBM Plex Mono", ui-monospace, monospace`, color: hover === h.i ? P.ink : P.ink2 });
            }
          });
          const step = Math.max(1, Math.ceil(n / 6));
          labelsNoOverlap(ctx, [...hits]
            .sort((a, b) => (hover === b.i) - (hover === a.i) || a.i - b.i)
            .filter(h => hover === h.i || h.i % step === 0 || h.i === n - 1)
            .map(h => ({ text: items[h.i].k, x: h.foot.x, y: h.foot.y, optional: hover !== h.i, color: hover === h.i ? P.ink : P.ink3, font: AXIS_FONT })));
          return hits;
        },
      };
    },

    /* The chance each algorithm is broken, by year: one ribbon per algorithm in
       its own lane, height = probability. The 50% line runs along the back wall
       and the model's Q-Day stands across every lane. Hover a point for the
       exact value; hover a legend entry to bring that algorithm forward. */
    curves(wrap, cfg) {
      const series = (cfg.series || []).map(sr => ({ ...sr, pts: (sr.pts || []).filter(p => Number.isFinite(p.yr) && Number.isFinite(p.p)) }))
        .filter(sr => sr.pts.length > 1);
      if (!series.length) return null;
      const years = series.flatMap(sr => sr.pts.map(p => p.yr));
      const y0 = Math.min(...years), y1 = Math.max(...years), q = Number(cfg.qYear);
      const hasQ = Number.isFinite(q) && q >= y0 && q <= y1;
      // Legend keys sit past any point index so hovering one highlights a whole series.
      const NONE = 999;
      return {
        height: 330, fitHeight: .66, yaw: -.26, tilt: .78,
        label: `Probability each algorithm is broken by year: ${series.map(sr => `${sr.label}${sr.half ? ` reaches 50% in ${sr.half}` : ""}`).join("; ")}`,
        legend: `<ul class="c3dLegend c3dLegendWide">${series.map((sr, si) => `<li data-i="${si * 1000 + NONE}"><i style="background:${esc(sr.color)}"></i><span>${esc(sr.label)}</span>${sr.half ? `<b>50% by ${esc(sr.half)}</b>` : "<b></b>"}<small></small></li>`).join("")}</ul>`,
        draw(g, ctx, { W, H, P, grow, hover }) {
          const x0 = W * .1, x1 = W * .8, top = H * .6, s = g.screen, lanes = series.length;
          const yBack = H * .18, yFront = H * .82, yw = yBack - H * .08;
          const laneY = i => (lanes === 1 ? (yBack + yFront) / 2 : yBack + (yFront - yBack) * i / (lanes - 1));
          const X = yr => x0 + (yr - y0) / Math.max(1, y1 - y0) * (x1 - x0);
          const hs = hover == null ? -1 : Math.floor(hover / 1000), hp = hover == null ? -1 : hover % 1000;
          [0, .25, .5, .75, 1].forEach(f => {
            const a = g.project(x0, yw, f * top), b = g.project(x1, yw, f * top);
            s.strokeStyle = f === .5 ? tint(P.ink2, .6) : P.line; s.lineWidth = 1; s.setLineDash(f === .5 ? [4, 4] : []);
            s.beginPath(); s.moveTo(a.x, a.y); s.lineTo(b.x, b.y); s.stroke(); s.setLineDash([]);
            text(s, `${f * 100}%`, a.x - 8, a.y, { color: f === .5 ? P.ink2 : P.ink3, align: "right" });
          });
          if (hasQ) {
            const xq = X(q), near = yFront + H * .1;
            poly(g, [[xq, yw, 0], [x1, yw, 0], [x1, near, 0], [xq, near, 0]], tint(P.bad, .07));
            const wall = poly(g, [[xq, yw, 0], [xq, near, 0], [xq, near, top * 1.04], [xq, yw, top * 1.04]], tint(P.bad, .08));
            s.strokeStyle = tint(P.bad, .5); s.lineWidth = 1; path(s, wall); s.stroke();
            const l = g.project(xq, yw, top * 1.09);
            text(s, `MODEL Q-DAY ${q}`, l.x + 6, l.y, { color: P.bad, align: "left", font: '600 10px "IBM Plex Mono", ui-monospace, monospace' });
          }
          const hits = [], ends = [];
          series.map((sr, si) => ({ sr, si, d: g.project((x0 + x1) / 2, laneY(si), 0).s }))
            .sort((a, b) => a.d - b.d)
            .forEach(({ sr, si }) => {
              const col = resolve(wrap, sr.color, P.brand), yy = laneY(si), focus = hs === si, dim = hs >= 0 && !focus;
              const pts = sr.pts.map(p => [X(p.yr), yy, p.p * top * grow]);
              const fa = g.project(x0, yy, 0), fb = g.project(x1, yy, 0);
              s.strokeStyle = tint(col, .22); s.lineWidth = 1; s.beginPath(); s.moveTo(fa.x, fa.y); s.lineTo(fb.x, fb.y); s.stroke();
              poly(g, [[pts[0][0], yy, 0], ...pts, [pts[pts.length - 1][0], yy, 0]], tint(col, dim ? .04 : focus ? .3 : .15));
              const line = pts.map(p => g.project(p[0], p[1], p[2]));
              s.strokeStyle = dim ? tint(col, .35) : col; s.lineWidth = focus ? 3 : 2; s.lineJoin = "round";
              s.setLineDash(sr.dash ? [5, 4] : []);
              s.beginPath(); line.forEach((qd, i) => (i ? s.lineTo(qd.x, qd.y) : s.moveTo(qd.x, qd.y))); s.stroke();
              s.setLineDash([]);
              sr.pts.forEach((p, pi) => {
                const qd = line[pi], on = focus && hp === pi, atQ = hasQ && p.yr === q;
                if (on) {
                  const f = g.project(pts[pi][0], yy, 0);
                  s.strokeStyle = tint(col, .6); s.lineWidth = 1; s.setLineDash([3, 3]);
                  s.beginPath(); s.moveTo(f.x, f.y); s.lineTo(qd.x, qd.y); s.stroke(); s.setLineDash([]);
                }
                if (on || atQ) { s.fillStyle = col; s.beginPath(); s.arc(qd.x, qd.y, on ? 5 : 3.8, 0, TAU); s.fill(); }
                hits.push({ i: si * 1000 + pi, x: qd.x, y: qd.y, r: 11, tip: [`${sr.label} · ${p.yr}`, `${Math.round(p.p * 100)}% chance broken`] });
              });
              ends.push({ si, end: line[line.length - 1], label: short(sr.label, 16), color: dim ? P.ink3 : focus ? P.ink : P.ink2 });
            });
          // Series names at the end of each ribbon; the focused one is placed first and the rest step aside.
          const nameFont = '500 10.5px "IBM Plex Sans", system-ui, sans-serif';
          setFont(s, nameFont);
          labelsNoOverlap(s, ends
            .sort((a, b) => (hs === b.si) - (hs === a.si) || a.end.y - b.end.y)
            .map(e => ({ text: e.label, x: e.end.x + 10 + s.measureText(e.label).width / 2, y: e.end.y, optional: true, color: e.color, font: nameFont })));
          const step = y1 - y0 > 10 ? 2 : 1, ticks = [];
          for (let yr = y0; yr <= y1; yr += step) {
            const f = g.project(X(yr), yFront + H * .14, 0);
            ticks.push({ text: String(yr), x: f.x, y: f.y, optional: true, color: P.ink3, font: AXIS_FONT });
          }
          labelsNoOverlap(s, ticks);
          return hits;
        },
      };
    },
  };

  /* ---------- a mounted chart ---------- */
  const mounted = new Set();
  document.fonts?.addEventListener?.("loadingdone", () => mounted.forEach(refresh => refresh()));
  function mount(wrap) {
    if (wrap.dataset.c3dOn || !window.airlockSpace) return;
    let cfg;
    try { cfg = JSON.parse(wrap.dataset.c3dCfg || "{}"); } catch { return; }
    const make = SPECS[wrap.dataset.c3d];
    const spec = make && make(wrap, cfg);
    if (!spec) return;
    wrap.dataset.c3dOn = "1";

    const fallback = document.createElement("div");
    fallback.className = "c3dFallback";
    while (wrap.firstChild) fallback.appendChild(wrap.firstChild);
    const box = document.createElement("div");
    box.className = "c3dStage";
    box.style.height = `${spec.height}px`;
    // No on-canvas "drag to turn" caption: it repeated on every chart. The affordance is the cursor,
    // and the instruction stays where assistive technology reads it, on the canvas label.
    box.innerHTML = `<canvas role="img" tabindex="0" aria-label="${esc(spec.label)}. Drag to turn, arrow keys to rotate, double-click to reset."></canvas><div class="c3dTip" hidden></div>`;
    wrap.classList.add("c3dOn");
    wrap.append(box);
    if (spec.legend) wrap.insertAdjacentHTML("beforeend", spec.legend);
    wrap.append(fallback);

    const canvas = box.querySelector("canvas"), tip = box.querySelector(".c3dTip"), ctx = canvas.getContext("2d");
    const yaw0 = spec.yaw ?? -.3, tilt0 = spec.tilt ?? .88;
    let W = 0, H = 0, ratio = 1, raf = 0, last = 0, visible = true, drawn = false;
    let yaw = yaw0, tilt = tilt0, yawT = yaw0, tiltT = tilt0, grow = still() ? 1 : 0, drag = null, hover = null, hits = [];
    let P = palette(wrap);

    function draw() {
      if (!W || !H) return;
      ctx.__c3dFont = "";   // a resize resets the context's font
      ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
      ctx.clearRect(0, 0, W, H);
      const g = window.airlockSpace.view(ctx, W, H, {
        tilt: Math.round(tilt * 50) / 50, yaw, yawRange: .55, lift: (spec.fitHeight || .5) * H / 2.2, pad: .03, inset: spec.inset || [.02, .02],
      });
      g.floorGrid(32, P.line, P.ground);
      g.lift = 0;
      hits = spec.draw(g, ctx, { W, H, P, grow: easeOut(grow), hover }) || [];
      drawn = true;
    }
    function frame(now) {
      raf = 0;
      if (!wrap.isConnected) { teardown(); return; }
      // Grow-in follows the wall clock: capped at 50ms a step, a page that could
      // only manage a few frames a second spent ten seconds redrawing every chart.
      const dt = last ? Math.min(.25, (now - last) / 1000) : 0;
      last = now;
      if (grow < 1) grow = still() ? 1 : Math.min(1, grow + dt / .9);
      yaw += (yawT - yaw) * .22; tilt += (tiltT - tilt) * .22;
      draw();
      if (visible && busy()) raf = requestAnimationFrame(frame);
      else last = 0;
    }
    const busy = () => grow < 1 || drag || Math.abs(yawT - yaw) > .001 || Math.abs(tiltT - tilt) > .001;
    const wake = () => { if (!raf) raf = requestAnimationFrame(frame); };
    function fit() {
      const rect = canvas.getBoundingClientRect();
      W = rect.width; H = rect.height;
      // Up to 2x, within a backing budget of ~700k pixels per chart.
      ratio = Math.max(1, Math.min(2, window.devicePixelRatio || 1, Math.sqrt(700000 / Math.max(1, W * H))));
      canvas.width = Math.max(1, Math.round(W * ratio));
      canvas.height = Math.max(1, Math.round(H * ratio));
      drawn = false;   // resizing clears the canvas
      wake();
    }
    function hitAt(ev) {
      const r = canvas.getBoundingClientRect(), x = ev.clientX - r.left, y = ev.clientY - r.top;
      let best = null, bestD = Infinity;
      hits.forEach(h => { const d = Math.hypot(h.x - x, h.y - y); if (d < h.r && d < bestD) { bestD = d; best = h; } });
      return best;
    }
    function showTip(h) {
      if (!h) { tip.hidden = true; return; }
      tip.innerHTML = `<b>${esc(h.tip[0])}</b><span>${esc(h.tip[1])}</span>`;
      tip.hidden = false;
      tip.style.left = `${clamp(h.x - tip.offsetWidth / 2, 6, Math.max(6, W - tip.offsetWidth - 6))}px`;
      tip.style.top = `${Math.max(6, h.y - tip.offsetHeight - 16)}px`;
    }
    function setHover(key) {
      if (key === hover) return;
      hover = key;
      wrap.querySelectorAll(".c3dLegend li").forEach(li => li.classList.toggle("on", String(li.dataset.i) === String(key)));
      wake();
    }
    canvas.addEventListener("pointerdown", ev => {
      drag = { x: ev.clientX, y: ev.clientY, yaw: yawT, tilt: tiltT, touch: ev.pointerType === "touch" };
      canvas.setPointerCapture(ev.pointerId);
      wake();
    });
    canvas.addEventListener("pointermove", ev => {
      if (drag) {
        const dx = ev.clientX - drag.x, dy = ev.clientY - drag.y;
        yawT = clamp(drag.yaw + dx * .006, -.55, .55);
        if (!drag.touch) tiltT = clamp(drag.tilt + dy * .004, .5, 1.1);
        tip.hidden = true;
        box.classList.add("dragging");
        wake();
        return;
      }
      const h = hitAt(ev);
      setHover(h ? h.i : null);
      showTip(h);
    });
    const endDrag = () => { drag = null; box.classList.remove("dragging"); wake(); };
    canvas.addEventListener("pointerup", endDrag);
    canvas.addEventListener("pointercancel", endDrag);
    canvas.addEventListener("pointerleave", () => { if (!drag) { setHover(null); tip.hidden = true; } });
    canvas.addEventListener("dblclick", () => { yawT = yaw0; tiltT = tilt0; wake(); });
    canvas.addEventListener("keydown", ev => {
      const step = { ArrowLeft: -.1, ArrowRight: .1 }[ev.key];
      if (step == null) return;
      ev.preventDefault(); yawT = clamp(yawT + step, -.55, .55); wake();
    });
    wrap.querySelector(".c3dLegend")?.addEventListener("pointerover", ev => {
      const li = ev.target.closest("li[data-i]");
      setHover(li ? Number(li.dataset.i) : null);
    });
    wrap.querySelector(".c3dLegend")?.addEventListener("pointerleave", () => setHover(null));

    const ro = new ResizeObserver(fit); ro.observe(canvas);
    /* A canvas keeps its picture while it is scrolled away, so coming back into
       view only needs a frame when the chart was still moving (or never drew).
       Redrawing every chart as it re-entered the viewport was most of the
       chart work while scrolling a long page. */
    const io = new IntersectionObserver(entries => {
      visible = entries.some(e => e.isIntersecting);
      if (visible && (!drawn || busy())) wake();
    });
    io.observe(canvas);
    const themeWatch = new MutationObserver(() => { resolved.delete(wrap); P = palette(wrap); wake(); });
    themeWatch.observe(document.documentElement, { attributeFilter: ["data-theme"] });
    // A chart drawn before its web font arrived is drawn again with it.
    const refresh = () => { drawn = false; if (visible) wake(); };
    mounted.add(refresh);
    function teardown() { ro.disconnect(); io.disconnect(); themeWatch.disconnect(); mounted.delete(refresh); }
    fit();
  }

  function scan(root = document) {
    root.querySelectorAll?.(".c3d[data-c3d]:not([data-c3d-on])").forEach(mount);
  }
  /* Rescan only when a mutation actually added something that is or holds a
     chart. Live panels (terminal logs, readouts, countdowns) mutate the page on
     every frame; each of those used to schedule a full-document query. */
  let queued = false;
  const holdsChart = node => node.nodeType === 1 && (node.classList.contains("c3d") || node.getElementsByClassName("c3d").length > 0);
  const observer = new MutationObserver(records => {
    if (queued) return;
    for (const record of records) {
      for (const node of record.addedNodes) {
        if (!holdsChart(node)) continue;
        queued = true;
        requestAnimationFrame(() => { queued = false; scan(); });
        return;
      }
    }
  });
  function start() {
    scan();
    observer.observe(document.body, { childList: true, subtree: true });
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start);
  else start();

  window.airlockCharts = { scan, mount };
})();
