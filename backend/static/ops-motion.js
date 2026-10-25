(() => {
  "use strict";
  /* ==========================================================================
     Operational panels

     Each panel is a small live graph with one large readout, beside a terminal
     log that plays in step with it:

       scan      probes fan out from a collector; endpoints land red, amber or
                 green as each handshake is classified
       rollout   a hybrid key-exchange policy goes canary → region by region →
                 one atomic switch
       evidence  inventory meets the policy gate; secrets are refused, the rest
                 is redacted, chained and signed into a Trust Passport
       blast     an RSA issuing CA is flagged, the impact runs down its chain,
                 then an ML-DSA replacement re-issues it in waves
       hndl      captured traffic sits sealed in an archive until a Q-Day sweep
                 shows what classical key exchange leaves readable

     Markup:  <div class="opsPanel" data-ops="scan"
                   data-ops-data='{"hosts":[…]}'   optional scene input
                   data-ops-tag="illustrative"     what the reader is looking at
                   data-ops-layout="compact"></div>

     Panels are labelled for what they are. Unless a caller passes real input,
     every figure in them is illustrative. Motion follows the same policy as the
     generative field: body[data-motion="paused"], reduced motion (which shows
     the finished frame), hidden tabs, and panels scrolled out of view.
     ========================================================================== */

  const reducedMotion = matchMedia("(prefers-reduced-motion: reduce)");

  const PALETTES = {
    dark: {
      ground: "#0A0E15", grid: "#121823", gridStrong: "#1A2130", edge: "#232C3D", idle: "#2A3345",
      text: "#E9EDF4", dim: "#8A94A6", acc: "#7B6BFF", flight: "#9D90FF",
      ok: "#4FB58B", warn: "#D4913F", bad: "#E46E62",
    },
    light: {
      ground: "#F7F8FA", grid: "#ECEFF3", gridStrong: "#DCE1E8", edge: "#CDD4DE", idle: "#B7C0CD",
      text: "#131925", dim: "#566072", acc: "#5A4BD6", flight: "#5A4BD6",
      ok: "#2B7F5B", warn: "#955C19", bad: "#B33E33",
    },
  };

  /* ---------- drawing kit ---------- */
  const rgba = new Map();
  function alpha(hex, a) {
    const key = hex + a;
    let out = rgba.get(key);
    if (!out) {
      const n = parseInt(hex.slice(1), 16);
      out = `rgba(${n >> 16},${(n >> 8) & 255},${n & 255},${a})`;
      rgba.set(key, out);
    }
    return out;
  }
  function rng(seed) {
    let s = seed >>> 0;
    return () => {
      s = (s + 0x6D2B79F5) >>> 0;
      let t = s;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }
  function hashText(text) {
    let h = 2166136261;
    for (let i = 0; i < text.length; i++) h = Math.imul(h ^ text.charCodeAt(i), 16777619);
    return (h >>> 0) / 4294967296;
  }
  const clamp = (v, a = 0, b = 1) => Math.min(b, Math.max(a, v));
  const lerp = (a, b, k) => a + (b - a) * k;
  const seg = (t, a, b) => clamp((t - a) / (b - a));
  const easeOut = k => 1 - Math.pow(1 - k, 3);
  const easeInOut = k => (k < .5 ? 4 * k * k * k : 1 - Math.pow(-2 * k + 2, 3) / 2);
  const fmt = n => Math.round(n).toLocaleString("en-US");
  const short = (s, n = 14) => (s.length > n ? s.slice(0, n - 1) + "…" : s);
  const esc = s => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/"/g, "&quot;");

  /* The kit draws flat on a plain 2D context and in depth on an airlockSpace
     view (space3d.js), so scenes are written once for both. */
  const D3 = ctx => Boolean(ctx && ctx.is3d);
  function grid(ctx, w, h, step, P) {
    if (D3(ctx)) { ctx.ground(P.ground); ctx.floorGrid(step, P.grid, P.ground, P.gridStrong); return; }
    ctx.fillStyle = P.ground;
    ctx.fillRect(0, 0, w, h);
    ctx.lineWidth = 1;
    ctx.strokeStyle = P.grid;
    ctx.beginPath();
    for (let x = (w % step) / 2; x <= w; x += step) { ctx.moveTo(Math.round(x) + .5, 0); ctx.lineTo(Math.round(x) + .5, h); }
    for (let y = (h % step) / 2; y <= h; y += step) { ctx.moveTo(0, Math.round(y) + .5); ctx.lineTo(w, Math.round(y) + .5); }
    ctx.stroke();
  }
  function edge(ctx, x1, y1, x2, y2, color, width = 1, dash = null) {
    ctx.strokeStyle = color;
    ctx.lineWidth = width;
    if (dash) ctx.setLineDash(dash);
    ctx.beginPath(); ctx.moveTo(x1, y1); ctx.lineTo(x2, y2); ctx.stroke();
    if (dash) ctx.setLineDash([]);
  }
  /* A packet in transit: bright head, fading tail along the segment. */
  function pulse(ctx, x1, y1, x2, y2, k, color, r = 2.6) {
    if (k <= 0 || k >= 1) return;
    if (D3(ctx)) {
      // In depth a packet arcs up off the link and comes down on the far node.
      const s = ctx.screen, len = Math.hypot(x2 - x1, y2 - y1), rise = Math.min(18, len * .16);
      const at = u => ctx.project(lerp(x1, x2, u), lerp(y1, y2, u), ctx.lift + Math.sin(u * Math.PI) * rise);
      const tk = Math.max(0, k - .24);
      let prev = at(tk);
      s.lineWidth = 2; s.lineCap = "round";
      for (let i = 1; i <= 7; i++) {
        const q = at(tk + (k - tk) * i / 7);
        s.strokeStyle = alpha(color, .9 * i / 7);
        s.beginPath(); s.moveTo(prev.x, prev.y); s.lineTo(q.x, q.y); s.stroke();
        prev = q;
      }
      s.lineCap = "butt";
      ctx.glow(prev.x, prev.y, r * 3.4 * prev.s, color, .5);
      s.fillStyle = color;
      s.beginPath(); s.arc(prev.x, prev.y, Math.max(1.2, r * prev.s), 0, Math.PI * 2); s.fill();
      return;
    }
    const hx = lerp(x1, x2, k), hy = lerp(y1, y2, k);
    const tk = Math.max(0, k - .22);
    const g = ctx.createLinearGradient(lerp(x1, x2, tk), lerp(y1, y2, tk), hx, hy);
    g.addColorStop(0, alpha(color, 0));
    g.addColorStop(1, alpha(color, .9));
    ctx.strokeStyle = g; ctx.lineWidth = 2;
    ctx.beginPath(); ctx.moveTo(lerp(x1, x2, tk), lerp(y1, y2, tk)); ctx.lineTo(hx, hy); ctx.stroke();
    ctx.fillStyle = color;
    ctx.beginPath(); ctx.arc(hx, hy, r, 0, Math.PI * 2); ctx.fill();
  }
  function node(ctx, x, y, r, fill, opts = {}) {
    if (D3(ctx)) {
      if (opts.square) ctx.cube(x, y, r, fill, opts);
      else ctx.ball(x, y, r, fill, opts);
      return;
    }
    if (opts.glow) {
      const g = ctx.createRadialGradient(x, y, 0, x, y, r * 4);
      g.addColorStop(0, alpha(opts.glow, .32 * (opts.glowA ?? 1)));
      g.addColorStop(1, alpha(opts.glow, 0));
      ctx.fillStyle = g;
      ctx.beginPath(); ctx.arc(x, y, r * 4, 0, Math.PI * 2); ctx.fill();
    }
    ctx.fillStyle = fill;
    if (opts.square) ctx.fillRect(x - r, y - r, r * 2, r * 2);
    else { ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2); ctx.fill(); }
    if (opts.ring) {
      ctx.strokeStyle = opts.ring; ctx.lineWidth = 1.2;
      if (opts.square) ctx.strokeRect(x - r - 3.5, y - r - 3.5, r * 2 + 7, r * 2 + 7);
      else { ctx.beginPath(); ctx.arc(x, y, r + 3.5, 0, Math.PI * 2); ctx.stroke(); }
    }
  }
  /* Handshake in progress: a short arc spinning around the node. */
  function spinner(ctx, x, y, r, t, color) {
    ctx.strokeStyle = color; ctx.lineWidth = 1.6;
    ctx.beginPath(); ctx.arc(x, y, r + 4, t * 7, t * 7 + 1.9); ctx.stroke();
  }
  function ripple(ctx, x, y, k, color, maxR = 26) {
    if (k <= 0 || k >= 1) return;
    ctx.strokeStyle = alpha(color, .7 * (1 - k)); ctx.lineWidth = 1.2;
    ctx.beginPath(); ctx.arc(x, y, 4 + easeOut(k) * maxR, 0, Math.PI * 2); ctx.stroke();
  }
  /* Assigning ctx.font re-parses the CSS font string and re-resolves the face,
     even when it is unchanged; with dozens of labels per frame it was the
     costliest line in the panels. Only these helpers set a font, and draw()
     forgets the cached value whenever the canvas may have been reset. */
  const MONO = [];
  function monoFont(s, size) {
    const font = MONO[size * 2] || (MONO[size * 2] = `500 ${size}px "IBM Plex Mono", ui-monospace, Consolas, monospace`);
    if (s.__opsFont !== font) { s.font = font; s.__opsFont = font; }
  }
  function label(ctx, text, x, y, color, align = "left", size = 10) {
    // Text always faces the reader: only its anchor is projected.
    const s = D3(ctx) ? ctx.screen : ctx;
    const q = D3(ctx) ? ctx.project(x, y, ctx.lift + 6) : { x, y };
    monoFont(s, size);
    s.fillStyle = color; s.textAlign = align; s.textBaseline = "middle";
    s.fillText(text, q.x, q.y);
  }
  /* A label a fixed number of screen pixels above (negative dy) or below a
     point. Offsets written in layout units would be squashed by the tilt. */
  function tag(ctx, text, x, y, dy, color, align = "center", size = 10) {
    const s = D3(ctx) ? ctx.screen : ctx;
    const q = D3(ctx) ? ctx.project(x, y) : { x, y };
    monoFont(s, size);
    s.fillStyle = color; s.textAlign = align; s.textBaseline = "middle";
    s.fillText(text, q.x, q.y + dy);
  }
  /* An upright translucent wall; flat scenes have no wall to draw. */
  function wall(ctx, x1, y1, x2, y2, height, color) {
    if (D3(ctx)) ctx.wall(x1, y1, x2, y2, height, color);
  }

  /* ---------- terminal ----------
     Lines are {at, kind, text}; [[...]] marks emphasis. The newest line types
     out, older lines stay put, and the view keeps the tail in sight. */
  /* Only the line being typed is rebuilt; finished lines stay in the DOM. The
     tail stays in sight through layout (see .opsTermLines in ops-motion.css)
     rather than by reading scrollHeight, which forced a synchronous layout of
     the whole page on every typed character. */
  class Term {
    constructor(el) {
      this.el = el; this.sig = ""; this.count = 0;
      this.box = document.createElement("div");
      this.box.className = "opsTermLines";
      el.replaceChildren(this.box);
    }
    line(line, typed, last) {
      const div = document.createElement("div");
      // Prefixed: host pages already style bare names like .cmd and .ok.
      div.className = "ln k-" + (line.kind || "plain");
      let budget = last && typed >= 0 ? typed : Infinity;
      for (const [j, part] of line.text.split(/\[\[|\]\]/).entries()) {
        if (budget <= 0) break;
        const chunk = part.slice(0, budget);
        budget -= chunk.length;
        if (j % 2) { const s = document.createElement("span"); s.className = "hi"; s.textContent = chunk; div.append(s); }
        else div.append(chunk);
      }
      if (last) { const c = document.createElement("span"); c.className = "opsCursor"; div.append(c); }
      return div;
    }
    render(lines, t, still) {
      let n = 0;
      while (n < lines.length && lines[n].at <= t) n++;
      const shown = n === lines.length ? lines : lines.filter(l => l.at <= t);
      n = shown.length;
      let typed = -1;
      if (n && !still) {
        const last = shown[n - 1];
        const plain = last.text.replace(/\[\[|\]\]/g, "");
        typed = Math.min(plain.length, Math.floor((t - last.at) * (last.kind === "cmd" ? 34 : 110)));
        if (typed >= plain.length) typed = -1;
      }
      const sig = n + ":" + typed;
      if (sig === this.sig) return;
      this.sig = sig;
      const box = this.box;
      if (!n) {
        const div = document.createElement("div"); div.className = "ln";
        const c = document.createElement("span"); c.className = "opsCursor"; div.append(c);
        box.replaceChildren(div);
        this.count = 0;
        return;
      }
      // A restarted loop shows fewer lines than before: start over.
      if (n < this.count || box.children.length !== Math.max(1, this.count)) { box.replaceChildren(); this.count = 0; }
      // The previous last line loses its cursor (and finishes typing); new lines follow it.
      for (let i = Math.max(0, this.count - 1); i < n; i++) {
        const div = this.line(shown[i], typed, i === n - 1);
        if (box.children[i]) box.children[i].replaceWith(div);
        else box.append(div);
      }
      this.count = n;
    }
  }

  const SCENES = {};

  /* ---------- hybrid rollout ---------- */
  SCENES.rollout = {
    title: "fleet · hybrid rollout", term: "morrow — rollout", period: 13,
    label: "Animated illustration: a hybrid post-quantum key exchange policy rolls out from a canary gateway, region by region, then switches atomically",
    setup() {
      const regions = [{ name: "region 1", cx: .2, off: 0 }, { name: "region 2", cx: .5, off: 1.5 }, { name: "region 3", cx: .8, off: 3 }];
      const nodes = [];
      regions.forEach((region, ri) => {
        const entry = ri === 0 ? [0, 0] : [0, 1];
        region.nodes = [];
        for (let r = 0; r < 3; r++) for (let c = 0; c < 4; c++) {
          const dist = Math.abs(c - entry[0]) + Math.abs(r - entry[1]);
          const n = { c, r, dist, x: region.cx + (c - 1.5) * .058, y: .52 + (r - 1) * .12 };
          n.start = ri === 0 && dist === 0 ? 1.4 : 3.3 + region.off + dist * .22;
          n.done = ri === 0 && dist === 0 ? 2.8 : n.start + .6;
          region.nodes.push(n); nodes.push(n);
        }
      });
      for (const region of regions) for (const n of region.nodes) {
        if (n.dist === 0) continue;
        n.from = region.nodes.find(m => m.dist === n.dist - 1 && Math.abs(m.c - n.c) + Math.abs(m.r - n.r) === 1);
      }
      regions[1].nodes[4].from = regions[0].nodes[7];
      regions[2].nodes[4].from = regions[1].nodes[7];
      regions[0].nodes[0].from = { x: .5, y: .13 };
      const log = [
        { at: 0, kind: "cmd", text: "morrow rollout --profile x25519mlkem768" },
        { at: .8, kind: "ok", text: "policy compiled  [[hybrid key exchange]]" },
        { at: 1.4, kind: "info", text: "canary  [[one gateway]] takes a small share of traffic" },
        { at: 2.8, kind: "ok", text: "canary checked against [[your latency and failure limits]]" },
        { at: 3.3, kind: "info", text: "propagate  [[region 1]]" },
        { at: 4.8, kind: "info", text: "propagate  [[region 2]]" },
        { at: 6.3, kind: "info", text: "propagate  [[region 3]]" },
        { at: 8.6, kind: "ok", text: "switch  [[every gateway]] on the hybrid profile" },
        { at: 9.2, kind: "", text: "rollback stays armed for the window you choose" },
        { at: 9.8, kind: "link", text: "/airlock-deployment" },
      ];
      return { regions, nodes, log, switchAt: 8.6 };
    },
    draw(ctx, w, h, t, S, P) {
      grid(ctx, w, h, 24, P);
      const px = .5 * w, py = .13 * h;
      const switched = t >= S.switchAt;
      const flash = seg(t, S.switchAt, S.switchAt + .9);
      S.regions.forEach((region, ri) => {
        const entry = region.nodes[ri === 0 ? 0 : 4];
        if (ri === 0) edge(ctx, px, py, entry.x * w, entry.y * h, alpha(P.acc, t >= .8 ? .35 : .12), 1, [3, 4]);
        for (const n of region.nodes) for (const m of region.nodes) {
          if ((m.c === n.c + 1 && m.r === n.r) || (m.r === n.r + 1 && m.c === n.c)) {
            const lit = t >= n.done && t >= m.done;
            edge(ctx, n.x * w, n.y * h, m.x * w, m.y * h, lit ? alpha(switched ? P.acc : P.ok, switched ? .5 - flash * .2 : .3) : P.edge);
          }
        }
      });
      for (const [a, b] of [[S.regions[0].nodes[7], S.regions[1].nodes[4]], [S.regions[1].nodes[7], S.regions[2].nodes[4]]]) {
        edge(ctx, a.x * w, a.y * h, b.x * w, b.y * h, t >= b.done ? alpha(P.ok, .3) : P.edge, 1, [2, 4]);
      }
      for (const n of S.nodes) if (n.from) pulse(ctx, n.from.x * w, n.from.y * h, n.x * w, n.y * h, seg(t, n.start - .35, n.start), P.flight, 2.4);
      let ok = 0;
      for (const n of S.nodes) {
        const x = n.x * w, y = n.y * h;
        if (t >= n.done) {
          ok++;
          node(ctx, x, y, 4.5, switched ? P.text : P.ok, { square: true, glow: switched ? P.acc : P.ok, glowA: switched ? 1 - flash * .5 : .5, ring: switched ? alpha(P.acc, .9 - flash * .5) : null });
          ripple(ctx, x, y, seg(t, n.done, n.done + .7), P.ok, 14);
        } else if (t >= n.start) {
          node(ctx, x, y, 4.5, alpha(P.flight, .25), { square: true, ring: P.flight });
        } else node(ctx, x, y, 4, P.idle, { square: true });
      }
      if (flash > 0 && flash < 1) {
        ctx.strokeStyle = alpha(P.acc, .5 * (1 - flash)); ctx.lineWidth = 1.5;
        ctx.strokeRect(.05 * w - flash * 8, .3 * h - flash * 8, .9 * w + flash * 16, .46 * h + flash * 16);
      }
      for (const region of S.regions) label(ctx, region.name, region.cx * w, .33 * h, t >= region.nodes[0].start ? P.text : P.dim, "center");
      node(ctx, px, py, 5, t >= .8 ? P.acc : P.idle, t >= .8 ? { glow: P.acc } : {});
      ripple(ctx, px, py, seg(t, .8, 1.7), P.acc, 22);
      label(ctx, "policy · hybrid key exchange", px + 14, py, t >= .8 ? P.text : P.dim);
      if (switched) return { v: "Switched", l: "every gateway on hybrid", s: "illustration · not live data" };
      return { v: String(ok), l: "gateways switched", s: "illustration · not live data" };
    },
  };

  /* ---------- airlock boundary ---------- */
  SCENES.evidence = {
    title: "boundary · evidence chain", term: "morrow — evidence", period: 13,
    label: "Animated illustration: inventory reaches the policy gate, secrets are refused, and the rest is redacted, hash-chained and signed into a Trust Passport",
    setup() {
      const random = rng(7);
      const sources = [{ name: "tls-scans", y: .2 }, { name: "cmdb", y: .4 }, { name: "kms-inventory", y: .6 }];
      const parts = [];
      let passed = 0, secrets = 0;
      for (let i = 0; i < 64; i++) {
        const src = i % 3 === 2 && random() < .5 ? 2 : Math.floor(random() * 3);
        const secret = random() < (src === 2 ? .45 : .12);
        const p = { src, secret, at: .3 + i * .13 + random() * .06, gy: lerp(sources[src].y, .4, .55) + (random() - .5) * .08 };
        p.gate = p.at + 1;
        if (!secret) { p.slot = passed; passed++; p.land = p.gate + .7; } else secrets++;
        parts.push(p);
      }
      const blocks = Math.floor(passed / 3);
      const seals = [];
      for (let b = 0; b < blocks; b++) seals.push(parts.find(p => p.slot === b * 3 + 2).land);
      const firstSecret = parts.find(p => p.secret && p.src === 2) || parts.find(p => p.secret) || parts[0];
      const signAt = seals[seals.length - 1] + .6;
      const log = [
        { at: 0, kind: "cmd", text: "morrow evidence build --sign" },
        { at: .4, kind: "ok", text: "collect [[tls-scans · cmdb · kms-inventory]]" },
        { at: 1.1, kind: "info", text: "policy gate  deny [[secrets, private keys, tokens]]" },
        { at: firstSecret.gate, kind: "warn", text: "refused  [[private key material]] never crosses the boundary" },
        { at: parts[parts.length - 1].gate, kind: "ok", text: "redact  [[sensitive fields]] · refuse [[secrets]]" },
        { at: seals[seals.length - 1], kind: "ok", text: "hash chain  [[sha-256]]" },
        { at: signAt, kind: "ok", text: "sign  [[ed25519]] with your signing key" },
        { at: signAt + .8, kind: "ok", text: "trust passport  [[issued]]" },
        { at: signAt + 1.4, kind: "link", text: "/trust-passport-demo" },
      ].sort((a, b) => a.at - b.at);
      return { sources, parts, blocks, seals, signAt, log };
    },
    draw(ctx, w, h, t, S, P) {
      grid(ctx, w, h, 24, P);
      const gx = .42 * w;
      const slot = b => ({ x: (.56 + (b % 6) * .065) * w, y: (.2 + (b / 6 | 0) * .2) * h });
      ctx.fillStyle = alpha(P.acc, .06); ctx.fillRect(gx - 5, .1 * h, 10, .6 * h);
      wall(ctx, gx, .1 * h, gx, .7 * h, 46, P.acc);
      edge(ctx, gx - 5, .1 * h, gx - 5, .7 * h, alpha(P.acc, .7));
      edge(ctx, gx + 5, .1 * h, gx + 5, .7 * h, alpha(P.acc, .7));
      label(ctx, "policy gate", gx, .05 * h, P.text, "center");
      let sealed = 0, redacted = 0, refused = 0;
      const fill = new Array(S.blocks).fill(0);
      for (const p of S.parts) {
        if (t >= p.gate) { if (p.secret) refused++; else redacted += 23; }
        if (!p.secret && t >= p.land && p.slot < S.blocks * 3) fill[p.slot / 3 | 0]++;
      }
      for (let b = 0; b < S.blocks; b++) {
        const { x, y } = slot(b);
        const done = t >= S.seals[b];
        if (done) sealed++;
        if (b > 0 && done) { const prev = slot(b - 1); edge(ctx, prev.x + 9, prev.y, x - 9, y, alpha(P.ok, .5)); }
        ctx.strokeStyle = done ? P.ok : P.edge; ctx.lineWidth = 1;
        ctx.strokeRect(x - 9, y - 9, 18, 18);
        if (done) { ctx.fillStyle = alpha(P.ok, .28); ctx.fillRect(x - 9, y - 9, 18, 18); ripple(ctx, x, y, seg(t, S.seals[b], S.seals[b] + .7), P.ok, 14); }
        else { ctx.fillStyle = alpha(P.flight, .45); ctx.fillRect(x - 9, y + 9 - fill[b] * 6, 18, fill[b] * 6); }
      }
      for (const p of S.parts) {
        if (t < p.at) continue;
        const sx = .1 * w, sy = S.sources[p.src].y * h, gy = p.gy * h;
        if (t < p.gate) {
          const k = easeOut(seg(t, p.at, p.gate));
          ctx.fillStyle = p.secret ? P.bad : alpha(P.text, .75);
          ctx.fillRect(lerp(sx, gx - 7, k) - 2, lerp(sy, gy, k) - 2, 4, 4);
        } else if (p.secret) {
          const k = seg(t, p.gate, p.gate + .7);
          if (k < 1) {
            ctx.fillStyle = alpha(P.bad, 1 - k);
            ctx.fillRect(gx - 9 - k * 60 - 2, gy + k * 10 - 2, 4, 4);
            ripple(ctx, gx, gy, k, P.bad, 12);
          }
        } else if (t < p.land && p.slot < S.blocks * 3) {
          const k = easeOut(seg(t, p.gate, p.land)), to = slot(p.slot / 3 | 0);
          ctx.fillStyle = P.flight;
          ctx.fillRect(lerp(gx + 7, to.x, k) - 2, lerp(gy, to.y, k) - 2, 4, 4);
        }
      }
      for (const src of S.sources) {
        node(ctx, .1 * w, src.y * h, 4.5, P.text, { square: true });
        label(ctx, src.name, .1 * w - 5, src.y * h - 15, P.dim);
      }
      const stamp = seg(t, S.signAt, S.signAt + .8);
      if (stamp > 0) {
        const x0 = .52 * w, y0 = .1 * h, x1 = .92 * w, y1 = .7 * h;
        const per = 2 * (x1 - x0 + y1 - y0), len = per * easeInOut(stamp);
        ctx.strokeStyle = P.acc; ctx.lineWidth = 1.5;
        ctx.setLineDash([len, per]);
        ctx.strokeRect(x0, y0, x1 - x0, y1 - y0);
        ctx.setLineDash([]);
        if (stamp >= 1) { ctx.fillStyle = P.ground; ctx.fillRect(x0 + 10, y0 - 7, 186, 14); label(ctx, "trust passport · ed25519", x0 + 16, y0, P.acc); }
      }
      if (t >= S.signAt + .8) return { v: "Signed", l: "trust passport issued", s: "illustration · not live data" };
      return { v: String(sealed), l: "evidence blocks sealed", s: "illustration · not live data" };
    },
  };

  /* ---------- harvest now, decrypt later ---------- */
  SCENES.hndl = {
    title: "archive · q-day exposure", term: "morrow — hndl", period: 12,
    label: "Animated illustration: encrypted traffic captured today stays sealed until a Q-Day sweep shows which flows classical key exchange leaves readable",
    setup(data) {
      const random = rng(21);
      const start = new Date().getFullYear();
      const parsed = parseInt(String(data.qday ?? ""), 10);
      const qday = Number.isFinite(parsed) ? clamp(parsed, start + 1, start + 25) : Math.max(start + 1, 2035);
      const end = Math.max(start + 10, qday + 3);
      const step = end - start > 14 ? 4 : 2;
      const cells = [];
      for (let i = 0; i < 72; i++) cells.push({ c: i % 12, r: i / 12 | 0, at: .3 + i * .068, y0: .14 + random() * .46, pq: random() < .32 });
      const pq = cells.filter(c => c.pq).length, readable = 72 - pq;
      const horizon = qday - start;
      const log = [
        { at: 0, kind: "cmd", text: "morrow hndl --secrecy-life <years your data must stay secret>" },
        { at: .4, kind: "info", text: `capture  [[${start}]] · encrypted traffic recorded today` },
        { at: 5.3, kind: "info", text: "recorded traffic  [[stays sealed today]]" },
        { at: 5.7, kind: "warn", text: `secrecy lifetime compared with  [[${qday}]]` },
        { at: 7.6, kind: "info", text: `sweep  [[${data.qdayLabel || "2035 · NIST disallows RSA and ECC"}]]` },
        { at: 9.6, kind: "bad", text: "classical key exchange  [[becomes readable]]" },
        { at: 10.1, kind: "ok", text: "ML-KEM key exchange  [[stays sealed]]" },
        { at: 10.7, kind: "info", text: "fix  enable hybrid key exchange before the horizon" },
      ];
      return { cells, pq, readable, log, start, end, step, qday, qdayLabel: data.qdayLabel ? "q-day · " + data.qdayLabel : "2035 · RSA/ECC disallowed" };
    },
    draw(ctx, w, h, t, S, P) {
      grid(ctx, w, h, 24, P);
      const bx = .47 * w, by = .12 * h, bw = .48 * w, bh = .5 * h;
      const cw = bw / 12, ch = bh / 6;
      const sweep = seg(t, 7.6, 9.6);
      const sx = bx + sweep * bw;
      ctx.strokeStyle = P.gridStrong; ctx.lineWidth = 1; ctx.strokeRect(bx - 6, by - 6, bw + 12, bh + 12);
      label(ctx, "recorded traffic", bx - 6, by - 15, P.dim);
      let captured = 0, readable = 0;
      for (const cell of S.cells) {
        const x = bx + cell.c * cw, y = by + cell.r * ch;
        const land = cell.at + .9;
        if (t >= cell.at && t < land) {
          const k = easeOut(seg(t, cell.at, land));
          ctx.fillStyle = cell.pq ? P.flight : alpha(P.text, .7);
          ctx.fillRect(lerp(.03 * w, x + cw / 2, k) - 2, lerp(cell.y0 * h, y + ch / 2, k) - 2, 4, 4);
        }
        if (t < land) { ctx.lineWidth = 1; ctx.strokeStyle = alpha(P.edge, .7); ctx.strokeRect(x + 2.5, y + 2.5, cw - 5, ch - 5); continue; }
        captured++;
        const swept = sweep > 0 && x + cw / 2 < sx;
        const open = !cell.pq && swept;
        if (open) readable++;
        ctx.fillStyle = open ? alpha(P.bad, .55) : cell.pq && swept ? alpha(P.ok, .22) : alpha(P.idle, .8);
        ctx.fillRect(x + 2, y + 2, cw - 4, ch - 4);
        if (cell.pq) { ctx.lineWidth = 1; ctx.strokeStyle = swept ? P.ok : alpha(P.flight, .8); ctx.strokeRect(x + 2.5, y + 2.5, cw - 5, ch - 5); }
        if (!open) { ctx.fillStyle = alpha(P.text, .35); ctx.fillRect(x + cw / 2 - 2, y + ch / 2 - 1, 4, 3); }
      }
      if (sweep > 0 && sweep < 1) {
        const g = ctx.createLinearGradient(sx - 40, 0, sx, 0);
        g.addColorStop(0, alpha(P.bad, 0)); g.addColorStop(1, alpha(P.bad, .35));
        ctx.fillStyle = g; ctx.fillRect(sx - 40, by - 6, 40, bh + 12);
        edge(ctx, sx, by - 10, sx, by + bh + 10, P.bad, 1.5); wall(ctx, sx, by - 10, sx, by + bh + 10, 40, P.bad);
      }
      const ty = .8 * h, yx = year => lerp(bx, bx + bw, (year - S.start) / (S.end - S.start));
      edge(ctx, bx, ty, bx + bw, ty, P.gridStrong);
      for (let year = S.start; year <= S.end; year += S.step) {
        edge(ctx, yx(year), ty - 3, yx(year), ty + 3, P.dim);
        label(ctx, String(year), yx(year), ty + 13, P.dim, "center", 9);
      }
      edge(ctx, yx(S.qday), ty - 8, yx(S.qday), ty + 3, P.bad, 1.5);
      label(ctx, S.qdayLabel, yx(S.qday), ty - 15, P.bad, "center", 9);
      const year = lerp(S.start, S.qday, easeInOut(seg(t, 5.6, 7.4)));
      node(ctx, yx(year), ty, 4, P.acc, { glow: P.acc });
      if (t < 5.6) return { v: String(captured), l: "recordings captured", s: "illustration · not live data" };
      if (t < 7.6) return { v: String(Math.floor(year)), l: "running forward", s: "illustration · not live data" };
      return { v: String(readable), l: "recordings readable", s: "illustration · classical key exchange" };
    },
  };

  /* ==========================================================================
     Live scenes. Everything drawn below comes from the workspace: the caller
     passes real records and the scene only decides timing. With no records a
     scene says so instead of inventing any.
     ========================================================================== */
  const usd = n => (n >= 1e6 ? "$" + (n / 1e6).toFixed(1).replace(/\.0$/, "") + "M" : n >= 1e3 ? "$" + Math.round(n / 1e3) + "k" : "$" + Math.round(n || 0));
  const kind = s => String(s || "node").replace(/_/g, " ");
  function emptyNote(ctx, w, h, P, title, sub) {
    label(ctx, title, w / 2, h / 2 - 9, P.text, "center", 12);
    label(ctx, sub, w / 2, h / 2 + 11, P.dim, "center", 10);
  }

  /* ---------- the latest scan ---------- */
  const SCAN_GROUPS = [["classical", "classical"], ["error", "probe errors"], ["unknown", "unclassified"], ["hybrid", "hybrid / pq"], ["unscanned", "not scanned"]];
  SCENES.scanLive = {
    title: "estate · latest scan", term: "morrow — scans",
    label: "Animated view of this workspace's latest TLS scan: each endpoint and how its key exchange was classified",
    setup(data) {
      const eps = Array.isArray(data.endpoints) ? data.endpoints : [];
      const groups = SCAN_GROUPS.map(([k, name]) => ({ k, name, list: eps.filter(e => e.state === k) })).filter(g => g.list.length);
      const count = groups.length;
      const gap = Math.min(.22, .64 / Math.max(1, count));
      const hubs = groups.map((g, i) => {
        const hub = { k: g.k, name: `${g.name} · ${g.list.length}`, x: .3, y: .43 + (i - (count - 1) / 2) * gap, arrive: .8 + i * .8 };
        const shown = g.list.slice(0, 9), rowsN = Math.ceil(shown.length / 3);
        hub.more = g.list.length - shown.length;
        hub.nodes = shown.map((e, j) => {
          const depart = hub.arrive + .2 + j * .32;
          return { ...e, depart, arrive: depart + .35, done: depart + .72,
            x: .52 + (j % 3) * .16, y: hub.y + (Math.floor(j / 3) - (rowsN - 1) / 2) * Math.min(.07, gap / Math.max(1, rowsN)) };
        });
        return hub;
      });
      const every = hubs.flatMap(hub => hub.nodes);
      const end = every.length ? Math.max(...every.map(n => n.done)) : 1;
      const scanned = eps.filter(e => e.state !== "unscanned");
      const classical = scanned.filter(e => e.state === "classical").length;
      const severe = n => /critical|high/.test(n.risk || "");
      const log = [data.scanId
        ? { at: .1, kind: "info", text: `latest scan [[${String(data.scanId).slice(0, 8)}]]${data.when ? ` · ${data.when}` : ""} · ${scanned.length} endpoint${scanned.length === 1 ? "" : "s"}` }
        : { at: .1, kind: "warn", text: "no completed scan yet · start one in TLS Scanner" }];
      every.forEach(n => log.push({
        at: n.done,
        kind: n.state === "hybrid" ? "ok" : n.state === "unscanned" ? "info" : n.state === "classical" && severe(n) ? "bad" : "warn",
        text: `[[${n.name}]]  ${n.detail || n.state}`,
      }));
      if (data.score != null) log.push({ at: end + .4, kind: "info", text: `quantum risk score [[${data.score}]]${data.level ? ` · ${data.level}` : ""}` });
      log.sort((a, b) => a.at - b.at);
      return { hubs, log, scanned: scanned.length, classical, total: eps.length, empty: !eps.length, period: Math.max(10, end + 5) };
    },
    draw(ctx, w, h, t, S, P) {
      grid(ctx, w, h, 24, P);
      if (S.empty) { emptyNote(ctx, w, h, P, "No endpoints yet", "Run a scan or add assets to see them here"); return { v: "—", l: "no scan data", s: "" }; }
      const cx = .07 * w, cy = .43 * h;
      const color = n => (n.state === "hybrid" ? P.ok : n.state === "unscanned" ? P.idle : n.state === "classical" && /critical|high/.test(n.risk || "") ? P.bad : P.warn);
      const names = w > 520;
      let doneScanned = 0, doneClassical = 0;
      for (const hub of S.hubs) {
        const hx = hub.x * w, hy = hub.y * h;
        edge(ctx, cx, cy, hx, hy, t >= hub.arrive ? alpha(P.flight, .35) : P.edge);
        pulse(ctx, cx, cy, hx, hy, seg(t, hub.arrive - .45, hub.arrive), P.flight);
        for (const n of hub.nodes) {
          const nx = n.x * w, ny = n.y * h, idle = n.state === "unscanned";
          edge(ctx, hx, hy, nx, ny, t >= n.done && !idle ? alpha(color(n), .32) : P.edge, 1, idle ? [3, 4] : null);
          if (!idle) pulse(ctx, hx, hy, nx, ny, seg(t, n.depart, n.arrive), P.flight, 2.2);
        }
      }
      for (const hub of S.hubs) {
        const hx = hub.x * w, hy = hub.y * h, reached = t >= hub.arrive;
        node(ctx, hx, hy, 4, reached ? P.text : P.idle, reached ? { glow: P.flight, glowA: .6 } : {});
        ripple(ctx, hx, hy, seg(t, hub.arrive, hub.arrive + .8), P.flight, 18);
        tag(ctx, hub.name, hx, hy, -16, reached ? P.text : P.dim, "center");
        if (hub.more > 0) label(ctx, `+${hub.more} more`, hx, hy + 15, P.dim, "center", 9);
        for (const n of hub.nodes) {
          const nx = n.x * w, ny = n.y * h;
          if (t >= n.done) {
            if (n.state !== "unscanned") { doneScanned++; if (n.state === "classical") doneClassical++; }
            if (n.state === "unscanned") node(ctx, nx, ny, 3.5, P.ground, { ring: P.idle });
            else { node(ctx, nx, ny, 4, color(n), { glow: color(n), glowA: .8 }); ripple(ctx, nx, ny, seg(t, n.done, n.done + .9), color(n), 16); }
          } else if (t >= n.arrive && n.state !== "unscanned") {
            node(ctx, nx, ny, 3.5, P.idle); spinner(ctx, nx, ny, 3.5, t, P.flight);
          } else node(ctx, nx, ny, 3, P.idle);
          // Three to a row leaves about fourteen characters before a label meets its neighbour.
          if (names) label(ctx, short(n.name, 14), nx + 10, ny, t >= n.done ? P.dim : alpha(P.dim, .5), "left", 9);
        }
      }
      node(ctx, cx, cy, 5, P.acc, { square: true, glow: P.acc, ring: alpha(P.acc, .5) });
      label(ctx, "collector", Math.max(cx, 30), cy + 20, P.dim, "center");
      return {
        v: doneScanned ? Math.round(doneClassical / doneScanned * 100) + "%" : S.scanned ? "…" : "0%",
        l: "classical key exchange",
        s: `${S.scanned} of ${S.total} endpoint${S.total === 1 ? "" : "s"} scanned`,
      };
    },
  };

  /* ---------- the certificate chain ---------- */
  SCENES.blastLive = {
    title: "pki · certificate chain", term: "morrow — pki",
    label: "Animated view of this workspace's certificate graph: impact moving from each root down to everything that trusts it",
    setup(data) {
      const nodes = (data.nodes || []).slice(0, 36).map(n => ({ ...n }));
      const ids = new Set(nodes.map(n => n.id));
      const edges = (data.edges || []).filter(e => ids.has(e.from) && ids.has(e.to) && e.from !== e.to);
      if (!nodes.length) return { empty: true, log: [{ at: .1, kind: "info", text: "no certificate graph yet · run a TLS scan" }], period: 6 };
      const layer = {};
      nodes.forEach(n => { layer[n.id] = 0; });
      for (let pass = 0; pass < nodes.length; pass++) {
        let moved = false;
        edges.forEach(e => { if (layer[e.to] < layer[e.from] + 1 && layer[e.from] < 8) { layer[e.to] = layer[e.from] + 1; moved = true; } });
        if (!moved) break;
      }
      const cols = [];
      nodes.forEach(n => { (cols[layer[n.id]] ||= []).push(n); });
      const ncol = cols.length;
      cols.forEach((col, ci) => col.forEach((n, ri) => {
        n.layer = ci;
        n.x = ncol === 1 ? .5 : .1 + ci * (.78 / (ncol - 1));
        n.y = .42 + (ri - (col.length - 1) / 2) * Math.min(.17, .5 / col.length);
        n.hit = .9 + ci * 1.1 + ri * .15;
      }));
      const byId = Object.fromEntries(nodes.map(n => [n.id, n]));
      const roots = nodes.filter(n => !edges.some(e => e.to === n.id) && edges.some(e => e.from === n.id));
      const reach = nodes.filter(n => n.layer > 0);
      const end = Math.max(...nodes.map(n => n.hit));
      const log = [
        { at: .1, kind: "info", text: `certificate graph · [[${nodes.length}]] nodes · [[${edges.length}]] links` },
        ...roots.slice(0, 2).map(r => ({ at: r.hit, kind: "warn", text: `[[${r.label}]]  ${kind(r.type)} · everything below it trusts it` })),
        ...reach.slice(0, 5).map(n => ({ at: n.hit, kind: n.risk >= 70 ? "bad" : "info", text: `[[${n.label}]]  ${kind(n.type)}${n.key ? ` · ${n.key}` : ""}${n.usd ? ` · ${usd(n.usd)}` : ""}` })),
        { at: end + .5, kind: reach.length ? "bad" : "ok", text: roots.length
          ? `if ${roots.length === 1 ? "the root" : "a root"} fails · [[${reach.length}]] dependent${reach.length === 1 ? "" : "s"} affected${data.exposure ? ` · [[${usd(data.exposure)}]] exposure` : ""}`
          : "no trust chain recorded between these nodes" },
      ].sort((a, b) => a.at - b.at);
      return { nodes, edges, byId, roots, reach: reach.length, exposure: data.exposure || 0, log, period: Math.max(10, end + 5.5) };
    },
    draw(ctx, w, h, t, S, P) {
      grid(ctx, w, h, 24, P);
      if (S.empty) { emptyNote(ctx, w, h, P, "No certificate graph yet", "Run a TLS scan to map issuers and services"); return { v: "—", l: "no chain data", s: "" }; }
      const X = n => n.x * w, Y = n => n.y * h;
      const isCa = n => /ca|root|issuer/.test(String(n.type || ""));
      for (const e of S.edges) {
        const a = S.byId[e.from], b = S.byId[e.to];
        const lit = t >= b.hit;
        edge(ctx, X(a), Y(a), X(b), Y(b), lit ? alpha(P.bad, .45) : P.edge, lit ? 1.4 : 1);
        pulse(ctx, X(a), Y(a), X(b), Y(b), seg(t, b.hit - .6, b.hit), P.bad, 2.6);
      }
      let reached = 0;
      for (const n of S.nodes) {
        const x = X(n), y = Y(n), root = S.roots.includes(n), hit = n.layer > 0 && t >= n.hit;
        if (hit) reached++;
        const fill = root ? (t >= n.hit ? P.bad : P.text) : hit ? P.bad : P.idle;
        node(ctx, x, y, isCa(n) ? 5.5 : 4.5, fill, { square: isCa(n), glow: root || hit ? P.bad : null, glowA: .7, ring: root && t >= n.hit ? alpha(P.bad, .5 + .5 * Math.sin(t * 5)) : null });
        ripple(ctx, x, y, seg(t, n.hit, n.hit + .9), P.bad, root ? 26 : 16);
        tag(ctx, kind(n.type).toUpperCase(), x, y, -30, P.dim, "center", 8.5);
        tag(ctx, short(n.label, 20), x, y, -18, hit || (root && t >= n.hit) ? P.text : P.dim, "center", 10);
        if (n.usd && hit) tag(ctx, usd(n.usd), x, y, 16, P.bad, "center", 9);
      }
      const finished = t >= Math.max(...S.nodes.map(n => n.hit)) + .2;
      return finished
        ? { v: String(S.reach), l: `affected if ${S.roots.length === 1 ? "the root fails" : "a root fails"}`, s: S.exposure ? `${usd(S.exposure)} modelled exposure` : `${S.nodes.length} nodes in the chain` }
        : { v: String(reached), l: "dependents reached", s: `${S.roots.length} root${S.roots.length === 1 ? "" : "s"} · ${S.nodes.length} nodes` };
    },
  };

  /* ---------- the HNDL archive ---------- */
  SCENES.hndlLive = {
    title: "archive · harvest exposure", term: "morrow — hndl",
    label: "Animated view of this workspace's HNDL model: each asset's captured traffic, and what becomes readable at the model's Q-Day",
    setup(data) {
      const assets = (data.assets || []).filter(a => Number(a.usd) > 0).slice(0, 12);
      if (!assets.length) return { empty: true, log: [{ at: .1, kind: "info", text: "no assets in the HNDL model yet" }], period: 6 };
      const total = assets.reduce((s, a) => s + Number(a.usd), 0);
      const cells = [];
      assets.forEach((a, ai) => {
        const n = Math.max(1, Math.round(a.usd / total * 48));
        for (let k = 0; k < n && cells.length < 60; k++) cells.push({ a: ai });
      });
      cells.forEach((c, i) => { c.c = i % 12; c.r = Math.floor(i / 12); c.at = .3 + i * .07; c.y0 = .15 + ((c.a * 37 + i * 11) % 50) / 100; });
      // Each cell's share of its asset's exposure, counted once rather than per cell per frame.
      const perAsset = new Map();
      cells.forEach(c => perAsset.set(c.a, (perAsset.get(c.a) || 0) + 1));
      cells.forEach(c => { c.share = Number(assets[c.a].usd) / perAsset.get(c.a); });
      const start = new Date().getFullYear();
      const parsed = parseInt(String(data.qday ?? ""), 10);
      const qday = Number.isFinite(parsed) ? clamp(parsed, start + 1, start + 25) : null;
      const readable = assets.filter(a => !a.pq);
      const readableUsd = readable.reduce((s, a) => s + Number(a.usd), 0);
      const captureEnd = cells[cells.length - 1].at + .9;
      const forwardAt = captureEnd + .3, sweepAt = forwardAt + 1.9, sweepEnd = sweepAt + 2;
      const log = [
        { at: .1, kind: "info", text: `[[${assets.length}]] assets modelled · [[${usd(total)}]] exposure` },
        ...[...assets].sort((a, b) => b.usd - a.usd).slice(0, 4).map((a, i) => ({ at: .6 + i * .9, kind: a.pq ? "ok" : "warn", text: `[[${a.name}]]  ${usd(a.usd)} · ${a.cls} · P(broken) ${Math.round((a.p || 0) * 100)}%` })),
        { at: forwardAt, kind: "info", text: qday ? `model Q-Day [[${qday}]]` : "no Q-Day year in the model" },
        { at: sweepEnd, kind: readable.length ? "bad" : "ok", text: `readable at Q-Day · [[${usd(readableUsd)}]] · ${readable.length} of ${assets.length} assets` },
        ...(assets.length > readable.length ? [{ at: sweepEnd + .5, kind: "ok", text: `[[${assets.length - readable.length}]] post-quantum assets stay sealed` }] : []),
      ].sort((a, b) => a.at - b.at);
      return { assets, cells, rows: Math.ceil(cells.length / 12), total, readableUsd, start, qday, end: Math.max(start + 6, (qday || start) + 2),
        forwardAt, sweepAt, sweepEnd, log, period: Math.max(12, sweepEnd + 5) };
    },
    draw(ctx, w, h, t, S, P) {
      grid(ctx, w, h, 24, P);
      if (S.empty) { emptyNote(ctx, w, h, P, "No HNDL model yet", "Add data-lifetime metadata to assets to model exposure"); return { v: "—", l: "no hndl data", s: "" }; }
      const bx = .47 * w, by = .12 * h, bw = .48 * w, bh = Math.min(.5 * h, S.rows * (.5 * h / 5));
      const cw = bw / 12, ch = bh / S.rows;
      const sweep = S.qday ? seg(t, S.sweepAt, S.sweepEnd) : 0;
      const sx = bx + sweep * bw;
      ctx.strokeStyle = P.gridStrong; ctx.lineWidth = 1; ctx.strokeRect(bx - 6, by - 6, bw + 12, bh + 12);
      label(ctx, "captured traffic · one cell per share of exposure", bx - 6, by - 15, P.dim, "left", 9);
      let captured = 0;
      for (const cell of S.cells) {
        const a = S.assets[cell.a], x = bx + cell.c * cw, y = by + cell.r * ch, land = cell.at + .9;
        if (t >= cell.at && t < land) {
          const k = easeOut(seg(t, cell.at, land));
          ctx.fillStyle = a.pq ? P.flight : alpha(P.text, .7);
          ctx.fillRect(lerp(.03 * w, x + cw / 2, k) - 2, lerp(cell.y0 * h, y + ch / 2, k) - 2, 4, 4);
        }
        if (t < land) { ctx.strokeStyle = alpha(P.edge, .7); ctx.strokeRect(x + 2.5, y + 2.5, cw - 5, ch - 5); continue; }
        captured += cell.share;
        const swept = sweep > 0 && x + cw / 2 < sx;
        ctx.fillStyle = swept && !a.pq ? alpha(P.bad, .25 + (a.p || 0) * .55) : swept && a.pq ? alpha(P.ok, .22) : alpha(P.idle, .8);
        ctx.fillRect(x + 2, y + 2, cw - 4, ch - 4);
        if (a.pq) { ctx.strokeStyle = swept ? P.ok : alpha(P.flight, .8); ctx.strokeRect(x + 2.5, y + 2.5, cw - 5, ch - 5); }
      }
      if (sweep > 0 && sweep < 1) {
        const g = ctx.createLinearGradient(sx - 40, 0, sx, 0);
        g.addColorStop(0, alpha(P.bad, 0)); g.addColorStop(1, alpha(P.bad, .35));
        ctx.fillStyle = g; ctx.fillRect(sx - 40, by - 6, 40, bh + 12);
        edge(ctx, sx, by - 10, sx, by + bh + 10, P.bad, 1.5); wall(ctx, sx, by - 10, sx, by + bh + 10, 40, P.bad);
      }
      const ty = Math.min(.82 * h, by + bh + .2 * h), yx = yr => lerp(bx, bx + bw, (yr - S.start) / (S.end - S.start));
      edge(ctx, bx, ty, bx + bw, ty, P.gridStrong);
      const step = S.end - S.start > 12 ? 4 : 2;
      for (let yr = S.start; yr <= S.end; yr += step) { edge(ctx, yx(yr), ty - 3, yx(yr), ty + 3, P.dim); label(ctx, String(yr), yx(yr), ty + 13, P.dim, "center", 9); }
      if (S.qday) { edge(ctx, yx(S.qday), ty - 8, yx(S.qday), ty + 3, P.bad, 1.5); label(ctx, `model q-day ${S.qday}`, yx(S.qday), ty - 15, P.bad, "center", 9); }
      const year = S.qday ? lerp(S.start, S.qday, easeInOut(seg(t, S.forwardAt, S.sweepAt))) : S.start;
      node(ctx, yx(year), ty, 4, P.acc, { glow: P.acc });
      if (t < S.forwardAt) return { v: usd(Math.min(captured, S.total)), l: "exposure captured", s: `${S.assets.length} assets in the model` };
      if (t < S.sweepAt) return { v: String(Math.floor(year)), l: "running forward", s: `model Q-Day ${S.qday}` };
      return { v: usd(S.readableUsd * sweep), l: "readable at q-day", s: `of ${usd(S.total)} modelled exposure` };
    },
  };

  /* ---------- the remediation pipeline ---------- */
  const PIPE_STAGES = [["open", "open"], ["progress", "in progress"], ["merged", "merged"], ["done", "verified"]];
  SCENES.pipeline = {
    title: "remediation · pipeline", term: "morrow — remediation",
    label: "Animated view of this workspace's remediation work: every migration task and fix moving into its current status",
    setup(data) {
      const all = Array.isArray(data.items) ? data.items : [];
      if (!all.length) return { empty: true, log: [{ at: .1, kind: "info", text: "no migration tasks or remediations yet" }], period: 6 };
      const items = all.slice(0, 56);
      const stages = PIPE_STAGES.map(([k, name], i) => ({ k, name, x: .3 + i * .19, list: items.filter(it => it.stage === k), total: all.filter(it => it.stage === k).length }));
      const spacing = Math.min(.24, 6 / items.length);
      let order = 0;
      stages.forEach(st => st.list.forEach((it, j) => {
        it.sx = st.x + ((j % 4) - 1.5) * .032;
        it.sy = .3 + Math.floor(j / 4) * .075;
        it.at = .5 + order++ * spacing;
        it.land = it.at + .7;
      }));
      const count = k => stages.find(s => s.k === k).total;
      const end = Math.max(...items.map(it => it.land));
      const fixes = all.filter(it => it.kind === "fix");
      const log = [
        { at: .1, kind: "info", text: `[[${all.length}]] items · ${all.length - fixes.length} migration task${all.length - fixes.length === 1 ? "" : "s"} · ${fixes.length} fix${fixes.length === 1 ? "" : "es"}` },
        ...fixes.slice(0, 3).map((f, i) => ({ at: 1 + i * .8, kind: f.stage === "done" ? "ok" : "info", text: `[[${f.name}]]  ${f.status}` })),
        ...(data.next ? [{ at: end * .6, kind: "warn", text: `next best fix · [[${data.next.name}]]${data.next.priority != null ? ` · priority ${data.next.priority}` : ""}` }] : []),
        { at: end + .3, kind: count("done") ? "ok" : "info", text: `[[${count("done")}]] verified · [[${count("open")}]] open · ${count("progress")} in progress` },
      ].sort((a, b) => a.at - b.at);
      return { items, stages, overflow: all.length - items.length, total: all.length, done: count("done"), open: count("open"), progress: count("progress"), log, period: Math.max(10, end + 5) };
    },
    draw(ctx, w, h, t, S, P) {
      grid(ctx, w, h, 24, P);
      if (S.empty) { emptyNote(ctx, w, h, P, "No remediation work yet", "Run a scan, then generate suggestions to fill the queue"); return { v: "—", l: "no remediation data", s: "" }; }
      const ix = .07 * w, iy = .5 * h;
      const tone = k => (k === "done" ? P.ok : k === "merged" ? alpha(P.ok, .6) : k === "progress" ? P.flight : P.warn);
      for (const st of S.stages) {
        const x = st.x * w;
        ctx.strokeStyle = alpha(P.edge, .8); ctx.setLineDash([2, 5]);
        ctx.beginPath(); ctx.moveTo(x, .22 * h); ctx.lineTo(x, .8 * h); ctx.stroke(); ctx.setLineDash([]);
        label(ctx, `${st.name} · ${st.total}`, x, .14 * h, st.total ? P.text : P.dim, "center", 10);
      }
      let landed = 0, done = 0;
      for (const it of S.items) {
        const tx = it.sx * w, ty = it.sy * h;
        if (t < it.at) continue;
        const k = easeOut(seg(t, it.at, it.land));
        const x = lerp(ix, tx, k), y = lerp(iy, ty, k);
        if (k < 1) { ctx.fillStyle = P.flight; ctx.globalAlpha = .9; ctx.fillRect(x - 2.5, y - 2.5, 5, 5); ctx.globalAlpha = 1; continue; }
        landed++; if (it.stage === "done") done++;
        node(ctx, tx, ty, it.kind === "fix" ? 4.5 : 3.6, tone(it.stage), { square: it.kind !== "fix", glow: it.kind === "fix" ? tone(it.stage) : null });
        ripple(ctx, tx, ty, seg(t, it.land, it.land + .6), tone(it.stage), 10);
      }
      node(ctx, ix, iy, 5, P.acc, { square: true, glow: P.acc, ring: alpha(P.acc, .5) });
      label(ctx, "intake", Math.max(ix, 26), iy + 20, P.dim, "center");
      if (S.overflow > 0) label(ctx, `+${S.overflow} not drawn`, w * .95, h * .86, P.dim, "right", 9);
      return landed < S.items.length
        ? { v: `${landed}`, l: "items placed", s: `${S.total} tracked` }
        : { v: `${S.done} / ${S.total}`, l: "verified closed", s: `${S.open} open · ${S.progress} in progress` };
    },
  };

  /* ---------- panels ---------- */
  function groundOf(host) {
    for (let el = host.parentElement; el; el = el.parentElement) {
      const match = /rgba?\(([^)]+)\)/.exec(getComputedStyle(el).backgroundColor);
      if (!match) continue;
      const [r, g, b, a = 1] = match[1].split(",").map(Number);
      if (a < .5) continue;
      return (.2126 * r + .7152 * g + .0722 * b) / 255 < .5 ? "dark" : "light";
    }
    return document.documentElement.dataset.theme === "light" ? "light" : "dark";
  }

  const panels = new Set();
  const io = "IntersectionObserver" in window ? new IntersectionObserver(entries => {
    for (const entry of entries) {
      const panel = entry.target.__opsPanel;
      if (!panel) continue;
      panel.visible = entry.isIntersecting;
      // The blinking cursor and tag pulse are CSS animations; they restyle on
      // every frame the page draws, so they rest while the panel is away.
      panel.host.classList.toggle("opsOffscreen", !panel.visible);
      if (panel.visible) { panel.dirty = true; wake(); }
    }
  }, { rootMargin: "120px" }) : null;
  const ro = "ResizeObserver" in window ? new ResizeObserver(entries => {
    for (const entry of entries) {
      const panel = entry.target.__opsPanel;
      if (!panel) continue;
      fit(panel);
      draw(panel);
    }
  }) : null;

  function fit(panel) {
    const rect = panel.canvas.getBoundingClientRect();
    // Sharp up to 1.5x, but never more than ~400k backing pixels per panel.
    const ratio = Math.max(1, Math.min(1.5, window.devicePixelRatio || 1, Math.sqrt(400000 / Math.max(1, rect.width * rect.height))));
    panel.w = rect.width; panel.h = rect.height; panel.ratio = ratio;
    panel.canvas.width = Math.max(1, Math.round(rect.width * ratio));
    panel.canvas.height = Math.max(1, Math.round(rect.height * ratio));
  }
  function theme(panel) {
    const name = groundOf(panel.host);
    panel.host.dataset.ground = name;
    panel.palette = PALETTES[name];
  }
  function draw(panel) {
    if (!panel.w || !panel.h) return;
    const { ctx } = panel;
    ctx.__opsFont = "";   // a resize resets the context's font
    ctx.setTransform(panel.ratio, 0, 0, panel.ratio, 0, 0);
    // Seen in depth when the camera module is present; the camera sways on its own clock.
    const view = window.airlockSpace
      ? window.airlockSpace.view(ctx, panel.w, panel.h, { tilt: .8, yaw: Math.sin((panel.cam || 0) * .3) * .17, yawRange: .17, lift: 16, pad: .02, inset: [.05, .08] })
      : ctx;
    const out = panel.scene.draw(view, panel.w, panel.h, panel.t, panel.S, panel.palette);
    for (const key of ["v", "l", "s"]) {
      if (out[key] !== panel.last[key]) { panel.out[key].textContent = out[key]; panel.last[key] = out[key]; }
    }
    panel.term.render(panel.S.log, panel.t, reducedMotion.matches);
    panel.dirty = false;
  }

  function mount(host) {
    if (!host || host.__opsMounted) return null;
    const scene = SCENES[host.dataset.ops];
    if (!scene) return null;
    host.__opsMounted = true;
    let data = {};
    try { data = JSON.parse(host.dataset.opsData || "{}") || {}; } catch { data = {}; }
    const compact = host.dataset.opsLayout === "compact";
    const tag = host.dataset.opsTag || "illustrative";
    host.setAttribute("role", "img");
    if (!host.hasAttribute("aria-label")) host.setAttribute("aria-label", `${scene.label} (${tag}).`);
    host.innerHTML = `<div class="opsGrid${compact ? " opsCompact" : ""}" aria-hidden="true">
      <div class="opsViz">${compact
        ? `<span class="opsTag opsTagFloat">${esc(tag)}</span>`
        : `<div class="opsBar"><span>${esc(scene.title)}</span><span class="opsTag">${esc(tag)}</span></div>`}
        <canvas></canvas><div class="opsReadout"><b></b><span></span><small></small></div></div>
      <div class="opsTerm">${compact ? "" : `<div class="opsBar"><span><i></i><i></i><i></i>${esc(scene.term)}</span></div>`}
        <div class="opsTermBody"></div></div></div>`;
    const canvas = host.querySelector("canvas");
    const readout = host.querySelector(".opsReadout");
    const S = scene.setup(data);
    const panel = {
      host, scene, S, canvas, ctx: canvas.getContext("2d"),
      period: S.period || scene.period,
      term: new Term(host.querySelector(".opsTermBody")),
      out: { v: readout.querySelector("b"), l: readout.querySelector("span"), s: readout.querySelector("small") },
      last: {}, t: 0, visible: true, started: false, dirty: true,
    };
    canvas.__opsPanel = panel;
    if (reducedMotion.matches || document.body.dataset.motion === "paused") panel.t = panel.period - .05;
    theme(panel);
    fit(panel);
    draw(panel);
    panels.add(panel);
    io?.observe(canvas);
    ro?.observe(canvas);
    wake();
    return panel;
  }
  function scan(root = document) {
    root.querySelectorAll?.("[data-ops]").forEach(mount);
  }

  /* One loop for every panel, at about thirty frames a second. It stops when
     nothing can move and is woken by anything that could change that. Between
     frames it sleeps on a timer instead of asking for every display frame and
     skipping most of them, and when drawing gets expensive (a slow machine,
     several panels) the gap widens so the panels take at most about a fifth of
     the main thread. */
  let raf = 0, last = 0, timer = 0, cost = 0;
  const gap = () => Math.min(100, Math.max(32, cost * 5));
  /* While the page scrolls, panels hold their current frame: a panel sliding
     past is not being read, and every frame drawn then competes with the
     scroll itself. Time does not advance, so the scene continues from where it
     stopped once scrolling has been quiet for SCROLL_REST ms. */
  const SCROLL_REST = 160;
  let scrollAt = -Infinity;
  addEventListener("scroll", () => { scrollAt = performance.now(); }, { passive: true, capture: true });
  function wake() {
    if (timer) { clearTimeout(timer); timer = 0; }
    if (!raf) raf = requestAnimationFrame(loop);
  }
  function later(delay) {
    if (delay <= 2) { raf = requestAnimationFrame(loop); return; }
    timer = setTimeout(() => { timer = 0; if (!raf) raf = requestAnimationFrame(loop); }, delay);
  }
  function loop(now) {
    raf = 0;
    const scrolled = performance.now() - scrollAt;
    if (scrolled < SCROLL_REST) { last = 0; if (!timer) later(SCROLL_REST - scrolled + 8); return; }
    if (last && now - last < gap() - 4) { if (!timer) later(gap() - 4 - (now - last)); return; }
    const started = performance.now();
    const dt = last ? Math.min(.1, (now - last) / 1000) : 0;
    last = now;
    const reduced = reducedMotion.matches;
    const still = reduced || document.hidden || document.body.dataset.motion === "paused";
    let moving = false;
    for (const panel of panels) {
      if (!panel.host.isConnected) {
        panels.delete(panel);
        io?.unobserve(panel.canvas);
        ro?.unobserve(panel.canvas);
        continue;
      }
      const rest = panel.period - .05;
      if (still) {
        // Held still before it ever ran, or under reduced motion: show the
        // finished frame rather than an empty graph.
        if ((reduced || !panel.started) && panel.t !== rest) { panel.t = rest; panel.dirty = true; }
      } else if (panel.visible) {
        panel.started = true;
        panel.t += dt;
        panel.cam = (panel.cam || 0) + dt;
        if (panel.t >= panel.period) { panel.t -= panel.period; panel.term.sig = ""; }
        panel.dirty = true;
        moving = true;
      }
      if (panel.dirty && panel.visible) draw(panel);
    }
    const spent = performance.now() - started;
    if (moving) {
      cost = cost ? cost * .8 + spent * .2 : spent;
      later(gap() - 4 - (performance.now() - now));
    } else last = 0;
  }

  function retheme() { for (const panel of panels) { theme(panel); panel.dirty = true; } wake(); }
  new MutationObserver(retheme).observe(document.documentElement, { attributeFilter: ["data-theme"] });
  new MutationObserver(wake).observe(document.body, { attributeFilter: ["data-motion"] });
  document.addEventListener("visibilitychange", wake);
  reducedMotion.addEventListener("change", () => { for (const panel of panels) panel.dirty = true; wake(); });

  window.airlockOps = { mount, scan, scenes: Object.keys(SCENES) };
  scan(document);
})();
