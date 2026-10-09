(() => {
  "use strict";
  /* ==========================================================================
     Airlock space — a perspective camera for 2D canvas animations.

     A scene is still laid out in flat canvas pixels. view() returns a stand-in
     for the 2D context that lays that layout on a tilted floor seen in
     perspective, turned slightly around its vertical axis. Paths, rectangles,
     arcs, gradients and text anchors are projected; `lift` sets how high above
     the floor the next shape is drawn. On top of that it offers solid shapes:
     shaded spheres and cubes on stems with floor shadows, upright walls, and a
     receding floor grid.

     const g = airlockSpace.view(ctx, width, height, { tilt, yaw, yawRange, lift, pad });
     g.lineTo(x, y)      // projected at g.lift
     g.ball(x, y, r, fill, { glow, stroke, core })
     g.project(x, y, z)  // → { x, y, s } in screen pixels, s = size scale
     g.screen            // the real context, for screen-space text and effects
     ========================================================================== */

  const TAU = Math.PI * 2;
  const fits = new Map();

  /* ---------- pre-rendered sprites ----------
     A shaded sphere is a filled circle plus two radial gradients (about 45us
     each, per node, per frame) and a glow one more gradient. Each is rendered
     once, at the device pixel size it is shown at, and stamped with drawImage
     (about 17us). Keys carry the colours and the device scale, so a theme or
     zoom change asks for new sprites; the cache is also emptied then so old
     ones do not linger. Text labels and the floor grid were measured the same
     way and are faster drawn directly (fillText ~4us against ~6us to stamp; a
     full-canvas grid bitmap cost more to copy than its lines to record), so
     they stay vectors. */
  const sprites = new Map();
  const makeCanvas = (w, h) => {
    if (typeof OffscreenCanvas === "function") return new OffscreenCanvas(w, h);
    const c = document.createElement("canvas");
    c.width = w; c.height = h;
    return c;
  };
  function remember(map, limit, key, make) {
    let out = map.get(key);
    if (out === undefined) {
      if (map.size >= limit) map.clear();
      out = make();
      map.set(key, out);
    }
    return out;
  }
  function flush() { sprites.clear(); }
  new MutationObserver(flush).observe(document.documentElement, { attributeFilter: ["data-theme"] });
  (function watchScale() {
    if (!window.matchMedia) return;
    matchMedia(`(resolution: ${window.devicePixelRatio || 1}dppx)`).addEventListener("change", () => { flush(); watchScale(); }, { once: true });
  })();

  /* A glow is the same gradient at any size, so one bitmap per colour and
     power-of-two radius serves every node; it is never scaled down by more
     than half, which keeps the falloff smooth. */
  function glowSprite(color, radius) {
    const R = radius <= 8 ? 8 : radius <= 16 ? 16 : radius <= 32 ? 32 : radius <= 64 ? 64 : 128;
    return remember(sprites, 600, "g|" + color + "|" + R, () => {
      const c = makeCanvas(R * 2, R * 2), g = c.getContext("2d");
      const grad = g.createRadialGradient(R, R, 0, R, R, R);
      grad.addColorStop(0, tint(color, 1)); grad.addColorStop(1, tint(color, 0));
      g.fillStyle = grad;
      g.beginPath(); g.arc(R, R, R, 0, TAU); g.fill();
      return c;
    });
  }
  /* The sphere body (fill, highlight, shade, outline, core) at a radius rounded
     to a quarter of a device pixel; the stamp scales it the last few percent. */
  function ballSprite(fill, R, S, stroke, strokeW, core) {
    return remember(sprites, 600, `b|${fill}|${R}|${S}|${stroke}|${strokeW}|${core}`, () => {
      const pad = Math.ceil((stroke ? strokeW * S / 2 : 0) + 2), mid = Math.ceil(R) + pad, size = mid * 2;
      const c = makeCanvas(size, size), g = c.getContext("2d");
      g.beginPath(); g.arc(mid, mid, R, 0, TAU);
      g.fillStyle = fill; g.fill();
      const hi = g.createRadialGradient(mid - R * .38, mid - R * .42, 0, mid - R * .2, mid - R * .2, R * 1.15);
      hi.addColorStop(0, "rgba(255,255,255,.55)"); hi.addColorStop(.45, "rgba(255,255,255,.08)"); hi.addColorStop(1, "rgba(255,255,255,0)");
      g.fillStyle = hi; g.fill();
      const lo = g.createRadialGradient(mid - R * .2, mid - R * .25, R * .35, mid, mid, R * 1.02);
      lo.addColorStop(0, "rgba(0,0,0,0)"); lo.addColorStop(1, "rgba(0,0,0,.38)");
      g.fillStyle = lo; g.fill();
      if (stroke) { g.strokeStyle = stroke; g.lineWidth = strokeW * S; g.stroke(); }
      if (core) { g.fillStyle = core; g.beginPath(); g.arc(mid, mid, Math.max(1.5 * S, R * .38), 0, TAU); g.fill(); }
      return { c, mid, size };
    });
  }
  /* Scenes ask for the same few tints every frame; parsing the colour with a
     regex each time showed up in profiles. */
  const tints = new Map();
  function tint(color, a) {
    const key = color + "|" + a;
    let out = tints.get(key);
    if (out === undefined) {
      out = parseTint(color, a);
      if (tints.size > 1024) tints.clear();
      tints.set(key, out);
    }
    return out;
  }
  function parseTint(color, a) {
    const c = String(color || "").trim();
    let m = /^#([0-9a-f]{3})$/i.exec(c);
    if (m) {
      const [r, g, b] = m[1].split("").map(h => parseInt(h + h, 16));
      return `rgba(${r},${g},${b},${a})`;
    }
    m = /^#([0-9a-f]{6})/i.exec(c);
    if (m) {
      const n = parseInt(m[1], 16);
      return `rgba(${n >> 16},${(n >> 8) & 255},${n & 255},${a})`;
    }
    m = /^rgba?\(([^)]+)\)/i.exec(c);
    if (m) {
      const [r, g, b, a0 = 1] = m[1].split(",").map(Number);
      return `rgba(${r},${g},${b},${a * a0})`;
    }
    return null;
  }

  /* World: x runs across, the layout's y runs into the screen as depth, z is
     height above the floor. The camera sits above and in front of the floor. */
  function rawProject(x, y, z, w, h, tilt, yaw, focal) {
    const X = x - w / 2, Z = y - h / 2;
    const cy = Math.cos(yaw), sy = Math.sin(yaw);
    const X1 = X * cy - Z * sy, Z1 = X * sy + Z * cy;
    const ct = Math.cos(tilt), st = Math.sin(tilt);
    const v = Z1 * ct - z * st;
    const depth = -Z1 * st - z * ct;
    const f = focal / (focal + depth);
    return { x: X1 * f, y: v * f, f };
  }

  /* The fit is computed across the whole yaw range, so the picture does not
     breathe in and out as the camera turns. */
  function fitFor(w, h, tilt, lift, range, pad, focal, inset) {
    const key = [w, h, tilt, lift, range, pad, inset[0], inset[1]].join("|");
    // Frame the area scenes actually draw in, not the empty margin around it.
    const x0 = w * inset[0], x1 = w * (1 - inset[0]), y0 = h * inset[1], y1 = h * (1 - inset[1]);
    let fit = fits.get(key);
    if (fit) return fit;
    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
    for (const yaw of [-range, 0, range]) {
      for (const [x, y] of [[x0, y0], [x1, y0], [x0, y1], [x1, y1]]) {
        for (const z of [0, lift * 2.2]) {
          const p = rawProject(x, y, z, w, h, tilt, yaw, focal);
          minX = Math.min(minX, p.x); maxX = Math.max(maxX, p.x);
          minY = Math.min(minY, p.y); maxY = Math.max(maxY, p.y);
        }
      }
    }
    const k = Math.min(w * (1 - 2 * pad) / Math.max(1, maxX - minX), h * (1 - 2 * pad) / Math.max(1, maxY - minY));
    fit = { k, ox: w / 2 - (minX + maxX) / 2 * k, oy: h / 2 - (minY + maxY) / 2 * k };
    if (fits.size > 64) fits.clear();
    fits.set(key, fit);
    return fit;
  }

  /* The context's drawing state, read and written through a view. Defined once
     here: defining them on every view (one per chart or panel per frame) was
     measurable on its own. */
  const ViewState = {};
  for (const prop of ["fillStyle", "strokeStyle", "lineWidth", "globalAlpha", "font", "textAlign", "textBaseline", "lineCap", "lineJoin", "lineDashOffset"]) {
    Object.defineProperty(ViewState, prop, { get() { return this.screen[prop]; }, set(value) { this.screen[prop] = value; } });
  }

  function view(ctx, w, h, opts = {}) {
    const tilt = opts.tilt ?? .8;
    const yaw = opts.yaw ?? 0;
    const range = Math.max(Math.abs(yaw), opts.yawRange ?? .2);
    const pad = opts.pad ?? .04;
    const base = opts.lift ?? 16;
    const focal = Math.max(w, h) * 1.8;
    const fit = fitFor(w, h, tilt, base, range, pad, focal, opts.inset || [0, 0]);
    const floorScale = Math.cos(tilt);
    // project() runs thousands of times per frame; the camera is fixed for the
    // life of a view, so its trigonometry is worked out once here.
    const cosY = Math.cos(yaw), sinY = Math.sin(yaw), cosT = floorScale, sinT = Math.sin(tilt);
    const halfW = w / 2, halfH = h / 2, fk = fit.k, fox = fit.ox, foy = fit.oy;
    let open = false;
    // Sprites are stamped only onto a plain scaled context (every caller sets
    // one); anything else is drawn as vectors.
    const m = ctx.getTransform ? ctx.getTransform() : null;
    const S = m && !m.b && !m.c && !m.e && !m.f && m.a === m.d && m.a > 0 ? m.a : 0;

    const V = {
      __proto__: ViewState,
      is3d: true, screen: ctx, lift: base, base, tilt, w, h,
      project(x, y, z = V.lift) {
        const X = x - halfW, Z = y - halfH;
        const X1 = X * cosY - Z * sinY, Z1 = X * sinY + Z * cosY;
        const v = Z1 * cosT - z * sinT;
        const f = focal / (focal + (-Z1 * sinT - z * cosT));
        return { x: fox + X1 * f * fk, y: foy + v * f * fk, s: f * fk };
      },

      /* ---------- the 2D context, projected ---------- */
      beginPath() { open = false; ctx.beginPath(); },
      closePath() { ctx.closePath(); },
      stroke() { ctx.stroke(); },
      fill() { ctx.fill(); },
      moveTo(x, y) { const q = V.project(x, y); ctx.moveTo(q.x, q.y); open = true; },
      lineTo(x, y) { const q = V.project(x, y); if (open) ctx.lineTo(q.x, q.y); else ctx.moveTo(q.x, q.y); open = true; },
      quadraticCurveTo(cx, cy, x, y) {
        const a = V.project(cx, cy), b = V.project(x, y);
        ctx.quadraticCurveTo(a.x, a.y, b.x, b.y); open = true;
      },
      ellipse(x, y, rx, ry, rot, a0, a1, ccw) {
        let span = a1 - a0;
        if (ccw) span = -(((a0 - a1) % TAU) + TAU) % TAU || -TAU;
        else if (span > TAU) span = TAU;
        const steps = Math.max(8, Math.ceil(Math.abs(span) / (TAU / 48)));
        const cr = Math.cos(rot || 0), sr = Math.sin(rot || 0);
        for (let i = 0; i <= steps; i++) {
          const a = a0 + span * i / steps;
          const ex = Math.cos(a) * rx, ey = Math.sin(a) * ry;
          const q = V.project(x + ex * cr - ey * sr, y + ex * sr + ey * cr);
          if (open) ctx.lineTo(q.x, q.y); else ctx.moveTo(q.x, q.y);
          open = true;
        }
      },
      arc(x, y, r, a0, a1, ccw) { V.ellipse(x, y, r, r, 0, a0, a1, ccw); },
      fillRect(x, y, rw, rh) { quad(x, y, rw, rh); ctx.fill(); },
      strokeRect(x, y, rw, rh) { quad(x, y, rw, rh); ctx.closePath(); ctx.stroke(); },
      clearRect(...a) { ctx.clearRect(...a); },
      setTransform(...a) { ctx.setTransform(...a); },
      setLineDash(d) { ctx.setLineDash(d); },
      measureText(t) { return ctx.measureText(t); },
      save() { ctx.save(); },
      restore() { ctx.restore(); },
      fillText(t, x, y) { const q = V.project(x, y); ctx.fillText(t, q.x, q.y); },
      createLinearGradient(x0, y0, x1, y1) {
        const a = V.project(x0, y0), b = V.project(x1, y1);
        return ctx.createLinearGradient(a.x, a.y, b.x, b.y);
      },
      createRadialGradient(x0, y0, r0, x1, y1, r1) {
        const a = V.project(x0, y0), b = V.project(x1, y1);
        return ctx.createRadialGradient(a.x, a.y, r0 * a.s, b.x, b.y, r1 * b.s);
      },

      /* ---------- the floor ---------- */
      ground(color) {
        ctx.fillStyle = color;
        ctx.fillRect(0, 0, w, h);
      },
      floorGrid(step, color, ground, strong) {
        const keep = V.lift;
        V.lift = 0;
        const x0 = -w * .2, x1 = w * 1.2, y0 = -h * .35, y1 = h * 1.15;
        ctx.lineWidth = 1;
        ctx.strokeStyle = color;
        const prev = ctx.globalAlpha;
        ctx.globalAlpha = prev * .9;
        ctx.beginPath(); open = false;
        let i = 0;
        for (let x = Math.floor(x0 / step) * step; x <= x1; x += step, i++) { V.moveTo(x, y0); V.lineTo(x, y1); }
        for (let y = Math.floor(y0 / step) * step; y <= y1; y += step) { V.moveTo(x0, y); V.lineTo(x1, y); }
        ctx.stroke();
        if (strong) {
          ctx.strokeStyle = strong;
          ctx.beginPath(); open = false;
          for (let x = Math.floor(x0 / (step * 4)) * step * 4; x <= x1; x += step * 4) { V.moveTo(x, y0); V.lineTo(x, y1); }
          for (let y = Math.floor(y0 / (step * 4)) * step * 4; y <= y1; y += step * 4) { V.moveTo(x0, y); V.lineTo(x1, y); }
          ctx.stroke();
        }
        ctx.globalAlpha = prev;
        // The far floor fades into the ground colour, like distance.
        const fogTop = tint(ground, 1), fogEnd = tint(ground, 0);
        if (fogTop) {
          const g = ctx.createLinearGradient(0, 0, 0, h * .42);
          g.addColorStop(0, fogTop); g.addColorStop(1, fogEnd);
          ctx.fillStyle = g;
          ctx.fillRect(0, 0, w, h * .42);
        }
        V.lift = keep;
      },

      /* ---------- solids ---------- */
      glow(sx, sy, radius, color, a = .35) {
        const inner = tint(color, a), outer = tint(color, 0);
        if (!inner || radius <= 0) return;
        if (S) {
          const prev = ctx.globalAlpha, sprite = glowSprite(color, radius * S);
          ctx.globalAlpha = prev * a;
          ctx.drawImage(sprite, sx - radius, sy - radius, radius * 2, radius * 2);
          ctx.globalAlpha = prev;
          return;
        }
        const g = ctx.createRadialGradient(sx, sy, 0, sx, sy, radius);
        g.addColorStop(0, inner); g.addColorStop(1, outer);
        ctx.fillStyle = g;
        ctx.beginPath(); ctx.arc(sx, sy, radius, 0, TAU); ctx.fill();
      },
      stem(x, y, z, color, a) {
        if (z <= 1) return;
        const top = V.project(x, y, z), foot = V.project(x, y, 0), prev = ctx.globalAlpha;
        ctx.globalAlpha = prev * a * .3;
        ctx.fillStyle = "rgba(0,0,0,.55)";
        const rr = Math.max(2, 5 * foot.s);
        ctx.beginPath(); ctx.ellipse(foot.x, foot.y, rr * 1.4, rr * 1.4 * floorScale, 0, 0, TAU); ctx.fill();
        ctx.globalAlpha = prev * a * .32;
        ctx.strokeStyle = color; ctx.lineWidth = 1;
        ctx.beginPath(); ctx.moveTo(foot.x, foot.y); ctx.lineTo(top.x, top.y); ctx.stroke();
        ctx.globalAlpha = prev;
      },
      ball(x, y, r, fill, o = {}) {
        const z = o.z ?? V.lift;
        const q = V.project(x, y, z), rr = Math.max(.6, r * q.s), prev = ctx.globalAlpha, A = o.alpha ?? 1;
        if (o.stemless !== true) V.stem(x, y, z, o.stroke || fill, A);
        if (o.glow) { ctx.globalAlpha = prev; V.glow(q.x, q.y, rr * 4, o.glow, .32 * (o.glowA ?? 1)); }
        ctx.globalAlpha = prev * A;
        // Stamped when the body composites as one: fully opaque (layer-by-layer
        // alpha differs from group alpha) with a solid outline.
        const R = Math.round(rr * S * 4) / 4;
        if (S && prev === 1 && A === 1 && !o.dash && R >= 1) {
          const sp = ballSprite(fill, R, S, o.stroke || "", o.stroke ? o.strokeW ?? 1.4 : 0, o.core || "");
          const k = rr / R;
          ctx.drawImage(sp.c, q.x - sp.mid * k, q.y - sp.mid * k, sp.size * k, sp.size * k);
        } else {
        ctx.fillStyle = fill;
        ctx.beginPath(); ctx.arc(q.x, q.y, rr, 0, TAU); ctx.fill();
        // Light from the upper left, shade toward the lower right.
        const hi = ctx.createRadialGradient(q.x - rr * .38, q.y - rr * .42, 0, q.x - rr * .2, q.y - rr * .2, rr * 1.15);
        hi.addColorStop(0, "rgba(255,255,255,.55)"); hi.addColorStop(.45, "rgba(255,255,255,.08)"); hi.addColorStop(1, "rgba(255,255,255,0)");
        ctx.fillStyle = hi; ctx.fill();
        const lo = ctx.createRadialGradient(q.x - rr * .2, q.y - rr * .25, rr * .35, q.x, q.y, rr * 1.02);
        lo.addColorStop(0, "rgba(0,0,0,0)"); lo.addColorStop(1, "rgba(0,0,0,.38)");
        ctx.fillStyle = lo; ctx.fill();
        if (o.stroke) {
          ctx.strokeStyle = o.stroke; ctx.lineWidth = o.strokeW ?? 1.4;
          if (o.dash) ctx.setLineDash(o.dash);
          ctx.stroke();
          if (o.dash) ctx.setLineDash([]);
        }
        if (o.core) {
          ctx.fillStyle = o.core;
          ctx.beginPath(); ctx.arc(q.x, q.y, Math.max(1.5, rr * .38), 0, TAU); ctx.fill();
        }
        }
        ctx.globalAlpha = prev;
        if (o.ring) {
          ctx.strokeStyle = o.ring; ctx.lineWidth = o.ringW ?? 1.2;
          const keep = V.lift; V.lift = z;
          V.beginPath(); V.arc(x, y, r + 3.5, 0, TAU); ctx.stroke();
          V.lift = keep;
        }
        return q;
      },
      cube(x, y, r, fill, o = {}) {
        const z = o.z ?? V.lift, zt = z + r * .9, zb = z - r * .9, prev = ctx.globalAlpha, A = o.alpha ?? 1;
        V.stem(x, y, zb, o.stroke || fill, A);
        const c = [[x - r, y - r], [x + r, y - r], [x + r, y + r], [x - r, y + r]];
        const top = c.map(([px, py]) => V.project(px, py, zt)), bot = c.map(([px, py]) => V.project(px, py, zb));
        const mid = V.project(x, y, z);
        if (o.glow) { ctx.globalAlpha = prev; V.glow(mid.x, mid.y, r * mid.s * 4, o.glow, .3 * (o.glowA ?? 1)); }
        ctx.globalAlpha = prev * A;
        const faces = [0, 1, 2, 3].map(i => {
          const j = (i + 1) % 4;
          return { pts: [top[i], top[j], bot[j], bot[i]], s: (top[i].s + top[j].s) / 2, shade: .22 + .14 * (i % 2) };
        }).sort((a, b) => a.s - b.s);
        for (const face of faces) {
          ctx.beginPath(); face.pts.forEach((p, i) => (i ? ctx.lineTo(p.x, p.y) : ctx.moveTo(p.x, p.y))); ctx.closePath();
          ctx.fillStyle = fill; ctx.fill();
          ctx.fillStyle = `rgba(0,0,0,${face.shade})`; ctx.fill();
        }
        ctx.beginPath(); top.forEach((p, i) => (i ? ctx.lineTo(p.x, p.y) : ctx.moveTo(p.x, p.y))); ctx.closePath();
        ctx.fillStyle = fill; ctx.fill();
        ctx.fillStyle = "rgba(255,255,255,.14)"; ctx.fill();
        if (o.ring) {
          ctx.strokeStyle = o.ring; ctx.lineWidth = o.ringW ?? 1.2;
          const keep = V.lift; V.lift = zt;
          V.strokeRect(x - r - 3.5, y - r - 3.5, r * 2 + 7, r * 2 + 7);
          V.lift = keep;
        }
        ctx.globalAlpha = prev;
        return mid;
      },
      wall(x1, y1, x2, y2, height, color, a = 1) {
        const fillC = tint(color, .1 * a), edgeC = tint(color, .75 * a), sideC = tint(color, .3 * a);
        if (!fillC) return;
        const zb = Math.max(0, V.lift - 6), zt = V.lift + height;
        const p = [V.project(x1, y1, zb), V.project(x2, y2, zb), V.project(x2, y2, zt), V.project(x1, y1, zt)];
        ctx.beginPath(); p.forEach((q, i) => (i ? ctx.lineTo(q.x, q.y) : ctx.moveTo(q.x, q.y))); ctx.closePath();
        const g = ctx.createLinearGradient(0, p[0].y, 0, p[3].y);
        g.addColorStop(0, tint(color, .02 * a)); g.addColorStop(1, fillC);
        ctx.fillStyle = g; ctx.fill();
        ctx.lineWidth = 1.2;
        ctx.strokeStyle = sideC;
        ctx.beginPath(); ctx.moveTo(p[0].x, p[0].y); ctx.lineTo(p[3].x, p[3].y); ctx.moveTo(p[1].x, p[1].y); ctx.lineTo(p[2].x, p[2].y); ctx.stroke();
        ctx.strokeStyle = edgeC;
        ctx.beginPath(); ctx.moveTo(p[3].x, p[3].y); ctx.lineTo(p[2].x, p[2].y); ctx.stroke();
      },
    };

    function quad(x, y, rw, rh) {
      const p = [V.project(x, y), V.project(x + rw, y), V.project(x + rw, y + rh), V.project(x, y + rh)];
      ctx.beginPath();
      p.forEach((q, i) => (i ? ctx.lineTo(q.x, q.y) : ctx.moveTo(q.x, q.y)));
      ctx.closePath();
      open = false;
    }

    return V;
  }

  window.airlockSpace = { view, tint, flush };
})();
