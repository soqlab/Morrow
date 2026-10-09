(() => {
  "use strict";
  /* ==========================================================================
     Airlock constellation

     A sparse field of points that drift very slowly and link up when they come
     near one another, like a network map at rest. Now and then a signal leaves
     one point and crosses a link to a neighbour, which answers with a brief
     ring. The geometry is parametric artwork derived from time and pointer
     position only — it never reads customer data.

     The earlier filament field was always in motion across the whole surface,
     which competed with the operational panels for attention. Here almost
     nothing moves at once, so the panels that do carry information stay the
     loudest thing on the page.

     Mount declaratively:  <div data-fabric="ambient"></div>
     or imperatively:      window.airlockFabric.mount(host, { form: "hero" })
     ========================================================================== */

  const FORMS = {
    // The hero is the artwork: denser, brighter, answers the pointer.
    hero: {
      density: 6400, minPoints: 60, maxPoints: 190, reach: 1.5, pulses: 18, lineGain: .5,
      fps: 30, dpr: 1.5, pixels: 700000, gain: 1, drift: 1, size: 1, themed: false,
    },
    // The ambient field sits behind workspaces people keep open all day:
    // sparser, fainter, fewer frames over fewer pixels.
    ambient: {
      density: 17000, minPoints: 36, maxPoints: 110, reach: 1.5, pulses: 6, lineGain: .34,
      fps: 20, dpr: 1, pixels: 320000, gain: .78, drift: .6, size: .85, themed: true,
    },
  };

  // Light points added to ink, dark points laid over paper — anything else
  // leaves one of the two grounds invisible.
  const THEMES = {
    dark: { node: [.78, .82, .90], accent: [.56, .50, 1], pulse: [.70, .66, 1], line: [.46, .51, .62], blendMode: "add", gain: 1 },
    light: { node: [.16, .20, .28], accent: [.35, .29, .84], pulse: [.35, .29, .84], line: [.30, .34, .42], blendMode: "over", gain: 1.1 },
  };

  /* A field follows the ground it actually sits on. Declared themes are only a
     fallback: a page can be dark while still carrying an old light attribute. */
  function groundTheme(host, declared) {
    for (let el = host.parentElement; el; el = el.parentElement) {
      const match = /rgba?\(([^)]+)\)/.exec(getComputedStyle(el).backgroundColor);
      if (!match) continue;
      const [r, g, b, a = 1] = match[1].split(",").map(Number);
      if (a < .5) continue;
      return (.2126 * r + .7152 * g + .0722 * b) / 255 < .5 ? "dark" : "light";
    }
    if (declared === "dark" || declared === "light") return declared;
    const root = document.documentElement.dataset.theme;
    if (root === "dark" || root === "light") return root;
    return matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
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
  const hash = n => { const x = Math.sin(n * 12.9898 + 78.233) * 43758.5453; return x - Math.floor(x); };

  /* One shared pool of points. The R2 low-discrepancy sequence spreads any
     prefix of it evenly, so a smaller surface simply uses fewer points and
     never shows a clump or a hole. */
  const POOL = 220;
  const POINTS = (() => {
    const random = seeded(20260913);
    return Array.from({ length: POOL }, (_, i) => ({
      u: (.5 + i * .7548776662 + (random() - .5) * .06) % 1,
      v: (.5 + i * .5698402910 + (random() - .5) * .06) % 1,
      phase: random() * 6.2832, speed: .6 + random() * .8,
      ax: .5 + random(), ay: .5 + random(),
      accent: random() < .12, size: .75 + random() * .6, twinkle: random() * 6.2832, depth: random(),
    }));
  })();

  const vertexSource = `
    attribute vec4 aData;               // x, y in CSS pixels, point size, alpha
    attribute float aKind;              // 0 node, 1 accent, 2 signal glow, 3 ring
    uniform vec2 uResolution;
    uniform float uRatio;
    varying float vAlpha, vKind;
    void main() {
      vec2 clip = aData.xy / uResolution * 2. - 1.;
      gl_Position = vec4(clip.x, -clip.y, 0., 1.);
      gl_PointSize = aData.z * uRatio;
      vAlpha = aData.w;
      vKind = aKind;
    }
  `;

  const fragmentSource = `
    precision mediump float;
    uniform float uShape, uGain;
    uniform vec3 uNode, uAccent, uPulse, uLine;
    varying float vAlpha, vKind;
    void main() {
      vec3 colour;
      float a;
      if (uShape < .5) {
        colour = uLine;
        a = vAlpha;
      } else {
        float d = length(gl_PointCoord - .5) * 2.;
        if (d > 1.) discard;
        if (vKind > 2.5) { colour = uPulse; a = smoothstep(.16, 0., abs(d - .78)); }
        else if (vKind > 1.5) { colour = uPulse; a = exp(-d * d * 5.) + smoothstep(.3, 0., d) * .7; }
        else if (vKind > .5) { colour = uAccent; a = smoothstep(1., .5, d); }
        else { colour = uNode; a = smoothstep(1., .45, d); }
        a *= vAlpha;
      }
      a = clamp(a * uGain, 0., 1.);
      gl_FragColor = vec4(colour * a, a);
    }
  `;

  function parseTint(value) {
    const match = /^#?([0-9a-f]{6})$/i.exec((value || "").trim());
    if (!match) return null;
    const number = parseInt(match[1], 16);
    return [(number >> 16 & 255) / 255, (number >> 8 & 255) / 255, (number & 255) / 255];
  }

  const STRIDE = 5;

  function createScene(canvas, options) {
    // Only real overrides may win: an absent data-attribute arrives as undefined
    // and would otherwise erase the form default it was meant to leave alone.
    const overrides = Object.fromEntries(Object.entries(options).filter(([, value]) => value !== undefined));
    const settings = { ...(FORMS[options.form] || FORMS.ambient), ...overrides };
    const host = canvas.parentElement;
    const locations = {};
    let gl, program, pointBuffer, lineBuffer, frame = 0, timer = 0;
    let elapsed = 6, lastFrame = 0, running = false, available = false;
    // Size is measured on resize, never per frame: reading clientWidth inside the
    // loop forces a synchronous style and layout pass whenever anything else on
    // the page has changed since the last frame.
    let cssW = 1, cssH = 1, drawCost = 0;
    let mode = 0, targetMode = 0;
    let palette = THEMES.dark, gain = settings.gain, blendMode = "add";
    const pointer = [0, 0], targetPointer = [0, 0];
    let pointerActive = 0, targetPointerActive = 0;

    const xs = new Float32Array(POOL), ys = new Float32Array(POOL), fs = new Float32Array(POOL).fill(1);
    const near = new Int16Array(POOL);
    const pointData = new Float32Array((POOL + settings.pulses * 8 + 4) * STRIDE);
    const MAX_LINKS = POOL * 8;
    const lineData = new Float32Array((MAX_LINKS + POOL) * 2 * STRIDE);

    function applyBlend() {
      gl.enable(gl.BLEND);
      if (blendMode === "over") gl.blendFunc(gl.ONE, gl.ONE_MINUS_SRC_ALPHA);
      else gl.blendFunc(gl.ONE, gl.ONE);
    }
    function syncTheme() {
      const theme = THEMES[settings.themed ? groundTheme(host, settings.theme) : "dark"];
      palette = {
        ...theme,
        accent: settings.warm || theme.accent,
        pulse: settings.cold || theme.pulse,
      };
      gain = settings.gain * theme.gain;
      blendMode = theme.blendMode;
      if (!available) return;
      applyBlend();
      draw();
    }
    function shader(type, source) {
      const result = gl.createShader(type);
      gl.shaderSource(result, source);
      gl.compileShader(result);
      if (!gl.getShaderParameter(result, gl.COMPILE_STATUS)) {
        gl.deleteShader(result);
        throw new Error("Constellation shader unavailable");
      }
      return result;
    }
    function dispose() {
      if (!gl) return;
      if (pointBuffer) gl.deleteBuffer(pointBuffer);
      if (lineBuffer) gl.deleteBuffer(lineBuffer);
      if (program) gl.deleteProgram(program);
      pointBuffer = lineBuffer = program = null;
    }
    function initialize() {
      try {
        gl = canvas.getContext("webgl", { alpha: true, antialias: true, depth: false, powerPreference: "low-power" });
        if (!gl) throw new Error("WebGL unavailable");
        const vertex = shader(gl.VERTEX_SHADER, vertexSource);
        const fragment = shader(gl.FRAGMENT_SHADER, fragmentSource);
        program = gl.createProgram();
        gl.attachShader(program, vertex);
        gl.attachShader(program, fragment);
        gl.linkProgram(program);
        gl.deleteShader(vertex);
        gl.deleteShader(fragment);
        if (!gl.getProgramParameter(program, gl.LINK_STATUS)) throw new Error("Constellation program unavailable");
        gl.useProgram(program);
        pointBuffer = gl.createBuffer();
        lineBuffer = gl.createBuffer();
        locations.data = gl.getAttribLocation(program, "aData");
        locations.kind = gl.getAttribLocation(program, "aKind");
        gl.enableVertexAttribArray(locations.data);
        gl.enableVertexAttribArray(locations.kind);
        for (const name of ["resolution", "ratio", "shape", "gain", "node", "accent", "pulse", "line"]) {
          locations[name] = gl.getUniformLocation(program, "u" + name[0].toUpperCase() + name.slice(1));
        }
        gl.disable(gl.DEPTH_TEST);
        gl.clearColor(0, 0, 0, 0);
        available = true;
        syncTheme();
        host.classList.add("scene-ready");
        canvas.dataset.state = "paused";
        resize();
      } catch {
        available = false;
        canvas.dataset.state = "unavailable";
        host.classList.remove("scene-ready");
        dispose();
      }
    }

    /* Where point i sits at time t. Three formations share every point, so a
       mode change is a rearrangement of the same field rather than a new one:
       0 the estate at rest, 1 two estates held apart by a boundary,
       2 a ring of evidence around a single seal. */
    function place(count, w, h) {
      const drift = settings.drift;
      // Depth: the points fill a slab that slowly turns and is seen in perspective,
      // so near points are larger and brighter than far ones. The pointer steers it.
      const turn = Math.sin(elapsed * .045 * drift) * .55 + (pointer[0] - .5) * .45 * pointerActive;
      const cosT = Math.cos(turn), sinT = Math.sin(turn), focal = Math.max(w, h) * 1.3;
      const m = mode;
      const m1 = Math.min(1, m), m2 = Math.max(0, m - 1);
      const aspect = h / w;
      const px = pointer[0] * w, py = pointer[1] * h;
      const repel = 120 * pointerActive;
      for (let i = 0; i < count; i++) {
        const p = POINTS[i];
        const ox = Math.sin(elapsed * .05 * p.speed + p.phase) * .028 * p.ax * drift;
        const oy = Math.cos(elapsed * .043 * p.speed + p.phase * 1.3) * .036 * p.ay * drift;
        const x1 = p.u < .5 ? .05 + p.u * .96 : .7 + (p.u - .5) * .56;
        const y1 = .08 + p.v * .84;
        const angle = p.u * 6.2832 + elapsed * .012 * drift;
        const radius = .25 + (p.v - .5) * .18;
        const x2 = .68 + Math.cos(angle) * radius * aspect;
        const y2 = .5 + Math.sin(angle) * radius;
        let x = p.u + (x1 - p.u) * m1, y = p.v + (y1 - p.v) * m1;
        x += (x2 - x) * m2; y += (y2 - y) * m2;
        x = (x + ox) * w; y = (y + oy) * h;
        const X = x - w / 2, Z = (p.depth - .5) * w * .8;
        const X1 = X * cosT - Z * sinT, Z1 = X * sinT + Z * cosT;
        const f = focal / (focal + Z1);
        x = w / 2 + X1 * f; y = h / 2 + (y - h / 2) * f;
        fs[i] = f;
        if (repel) {
          const dx = x - px, dy = y - py, d = Math.hypot(dx, dy);
          if (d < repel && d > .01) {
            const push = (1 - d / repel) ** 2 * 16;
            x += dx / d * push; y += dy / d * push;
          }
        }
        xs[i] = x; ys[i] = y;
      }
    }

    function draw() {
      if (!available) return;
      const w = cssW, h = cssH;
      const count = Math.max(settings.minPoints, Math.min(settings.maxPoints, POOL, Math.round(w * h / settings.density)));
      const reach = Math.sqrt(settings.density) * settings.reach, reach2 = reach * reach;
      place(count, w, h);

      // Links between every pair close enough to see each other. Pairs are
      // rejected on one axis first and compared squared; Math.hypot on every
      // pair was the single largest cost of the whole page.
      let lines = 0;
      const pushLine = (x1, y1, x2, y2, alpha) => {
        const o = lines * 2 * STRIDE;
        lineData[o] = x1; lineData[o + 1] = y1; lineData[o + 2] = 1; lineData[o + 3] = alpha; lineData[o + 4] = 0;
        lineData[o + 5] = x2; lineData[o + 6] = y2; lineData[o + 7] = 1; lineData[o + 8] = alpha; lineData[o + 9] = 0;
        lines++;
      };
      outer: for (let i = 0; i < count; i++) {
        const xi = xs[i], yi = ys[i];
        for (let j = i + 1; j < count; j++) {
          const dx = xi - xs[j];
          if (dx >= reach || dx <= -reach) continue;
          const dy = yi - ys[j];
          if (dy >= reach || dy <= -reach) continue;
          const d2 = dx * dx + dy * dy;
          if (d2 >= reach2) continue;
          if (lines >= MAX_LINKS) break outer;
          pushLine(xi, yi, xs[j], ys[j], Math.pow(1 - Math.sqrt(d2) / reach, 1.6) * settings.lineGain * Math.min(1.15, fs[i] * fs[j]));
        }
      }
      // The pointer joins the field as one more point.
      if (pointerActive > .01) {
        const px = pointer[0] * w, py = pointer[1] * h, pr = reach * 1.3, pr2 = pr * pr;
        for (let i = 0; i < count; i++) {
          const dx = xs[i] - px, dy = ys[i] - py, d2 = dx * dx + dy * dy;
          if (d2 < pr2 && lines < MAX_LINKS + POOL) pushLine(px, py, xs[i], ys[i], (1 - Math.sqrt(d2) / pr) * .8 * pointerActive);
        }
      }

      let points = 0;
      const pushPoint = (x, y, size, alpha, kind) => {
        const o = points * STRIDE;
        pointData[o] = x; pointData[o + 1] = y; pointData[o + 2] = size; pointData[o + 3] = alpha; pointData[o + 4] = kind;
        points++;
      };
      for (let i = 0; i < count; i++) {
        const p = POINTS[i];
        const shimmer = .5 + .5 * Math.sin(elapsed * .5 * p.speed + p.twinkle);
        const size = (p.accent ? 4.2 : 3) * p.size * settings.size * fs[i];
        const nearness = Math.min(1, Math.max(.28, (fs[i] - .62) / .7));
        pushPoint(xs[i], ys[i], size, (p.accent ? .72 + shimmer * .28 : .5 + shimmer * .22) * nearness, p.accent ? 1 : 0);
      }

      /* Signals. Each slot is a pure function of elapsed time: which point sends,
         which neighbour receives, and how far along the link it is. Nothing is
         remembered between frames, so a paused field redraws identically. */
      for (let k = 0; k < settings.pulses; k++) {
        const cycle = 2.6 + hash(k * 7.1) * 2.2;
        const shifted = elapsed / cycle + hash(k * 3.3) * 10;
        const round = Math.floor(shifted), phase = shifted - round;
        const from = Math.floor(hash(k * 131 + round * 977) * count);
        // One pass collects the sender's neighbours in index order; the pick is
        // the same neighbour the earlier count-then-search found.
        const pick = hash(k * 57 + round * 313), fx = xs[from], fy = ys[from], r2 = reach2 * .9025;
        let seen = 0;
        for (let j = 0; j < count; j++) {
          if (j === from) continue;
          const dx = fx - xs[j], dy = fy - ys[j];
          if (dx * dx + dy * dy < r2) near[seen++] = j;
        }
        if (!seen) continue;
        const to = near[Math.floor(pick * seen)];
        const travel = Math.min(1, phase / .62);
        const eased = travel < .5 ? 2 * travel * travel : 1 - (-2 * travel + 2) ** 2 / 2;
        const scale = settings.size * fs[to];
        if (travel < 1) {
          // Brighten the link being crossed, then the head and a short tail.
          pushLine(xs[from], ys[from], xs[to], ys[to], .55 * Math.sin(travel * Math.PI) + .1);
          for (let s = 3; s >= 0; s--) {
            const back = Math.max(0, eased - s * .06);
            const x = xs[from] + (xs[to] - xs[from]) * back, y = ys[from] + (ys[to] - ys[from]) * back;
            if (s === 0) {
              pushPoint(x, y, 18 * scale, .9, 2);
              pushPoint(x, y, 3.6 * scale, 1, 1);
            } else pushPoint(x, y, 5 * scale, .35 / s, 2);
          }
        } else {
          // The receiver answers with a ring that opens and fades.
          const answer = (phase - .62) / .38;
          pushPoint(xs[to], ys[to], (8 + answer * 22) * scale, (1 - answer) * .85, 3);
          pushPoint(xs[to], ys[to], 12 * scale, (1 - answer) * .7, 2);
        }
      }
      if (pointerActive > .01) pushPoint(pointer[0] * w, pointer[1] * h, 5 * settings.size, pointerActive, 1);

      gl.clear(gl.COLOR_BUFFER_BIT);
      gl.uniform2f(locations.resolution, w, h);
      gl.uniform1f(locations.ratio, canvas.width / w);
      gl.uniform1f(locations.gain, gain);
      gl.uniform3fv(locations.node, palette.node);
      gl.uniform3fv(locations.accent, palette.accent);
      gl.uniform3fv(locations.pulse, palette.pulse);
      gl.uniform3fv(locations.line, palette.line);

      const bind = (buffer, data, length) => {
        gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
        gl.bufferData(gl.ARRAY_BUFFER, data.subarray(0, length), gl.DYNAMIC_DRAW);
        gl.vertexAttribPointer(locations.data, 4, gl.FLOAT, false, STRIDE * 4, 0);
        gl.vertexAttribPointer(locations.kind, 1, gl.FLOAT, false, STRIDE * 4, 16);
      };
      if (lines) {
        bind(lineBuffer, lineData, lines * 2 * STRIDE);
        gl.uniform1f(locations.shape, 0);
        gl.drawArrays(gl.LINES, 0, lines * 2);
      }
      bind(pointBuffer, pointData, points * STRIDE);
      gl.uniform1f(locations.shape, 1);
      gl.drawArrays(gl.POINTS, 0, points);
    }
    function resize() {
      if (!available) return;
      const width = Math.max(1, canvas.clientWidth), height = Math.max(1, canvas.clientHeight);
      const ratio = Math.min(window.devicePixelRatio || 1, settings.dpr, Math.sqrt(settings.pixels / (width * height)));
      cssW = width; cssH = height;
      const bw = Math.round(width * ratio), bh = Math.round(height * ratio);
      // Assigning width clears the drawing buffer even when unchanged; skip it then.
      if (canvas.width !== bw || canvas.height !== bh) {
        canvas.width = bw;
        canvas.height = bh;
        gl.viewport(0, 0, bw, bh);
      }
      draw();
    }
    /* Frame pacing. The field wants 20-30 frames a second, so between frames it
       sleeps on a timer rather than asking for every display frame and skipping
       most of them, and it stretches the gap further when a frame is costly
       (slow machine, busy page) so it never takes more than ~1/8 of the thread. */
    const interval = () => Math.min(250, Math.max(1000 / settings.fps, drawCost * 8));
    function schedule(now) {
      const wait = interval() - (performance.now() - now) - 4;
      if (wait > 4) timer = setTimeout(() => { timer = 0; if (running && !frame) frame = requestAnimationFrame(tick); }, wait);
      else frame = requestAnimationFrame(tick);
    }
    function tick(now) {
      frame = 0;
      if (!running) return;
      if (!lastFrame) lastFrame = now;
      const delta = now - lastFrame;
      if (delta < interval() - 6) { if (!timer) schedule(now - delta); return; }
      elapsed += Math.min(delta, 250) / 1000;
      lastFrame = now;
      const blend = Math.min(3, delta * settings.fps / 1000 || 1);
      mode += (targetMode - mode) * Math.min(1, .075 * blend);
      pointer.forEach((value, i) => { pointer[i] += (targetPointer[i] - value) * Math.min(1, .12 * blend); });
      pointerActive += (targetPointerActive - pointerActive) * Math.min(1, .1 * blend);
      const started = performance.now();
      draw();
      const cost = performance.now() - started;
      drawCost = drawCost ? drawCost * .85 + cost * .15 : cost;
      schedule(now);
    }
    function setRunning(value) {
      const next = Boolean(value && available);
      if (running === next) return;
      running = next;
      cancelAnimationFrame(frame);
      clearTimeout(timer);
      frame = timer = 0;
      lastFrame = 0;
      canvas.dataset.state = available ? (running ? "running" : "paused") : "unavailable";
      if (running) frame = requestAnimationFrame(tick);
    }
    function setMode(value) {
      targetMode = Math.max(0, Math.min(2, Number(value) || 0));
      canvas.dataset.mode = String(targetMode);
      if (!running) { mode = targetMode; draw(); }
    }
    if (settings.pointer !== false) {
      host.addEventListener("pointermove", event => {
        if (!running || event.pointerType !== "mouse") return;
        const bounds = canvas.getBoundingClientRect();
        targetPointer[0] = (event.clientX - bounds.left) / bounds.width;
        targetPointer[1] = (event.clientY - bounds.top) / bounds.height;
        if (!targetPointerActive) { pointer[0] = targetPointer[0]; pointer[1] = targetPointer[1]; }
        targetPointerActive = 1;
      }, { passive: true });
      host.addEventListener("pointerleave", () => { targetPointerActive = 0; });
    }
    canvas.addEventListener("webglcontextlost", event => {
      event.preventDefault();
      setRunning(false);
      available = false;
      canvas.dataset.state = "unavailable";
      host.classList.remove("scene-ready");
    });
    canvas.addEventListener("webglcontextrestored", () => {
      initialize();
      document.dispatchEvent(new Event("airlock:scene-ready"));
    });
    window.addEventListener("resize", resize, { passive: true });
    // The host can change size without the window doing so (a sidebar, a
    // stylesheet arriving late); the cached size must follow it.
    if ("ResizeObserver" in window) new ResizeObserver(() => resize()).observe(canvas);
    initialize();
    return { canvas, setRunning, setMode, resize, syncTheme, get available() { return available; } };
  }

  const scenes = [];
  function mount(host, options = {}) {
    if (!host) return null;
    const canvas = host.querySelector("canvas") || host.appendChild(document.createElement("canvas"));
    const scene = createScene(canvas, options);
    scenes.push(scene);
    return scene;
  }

  // Fields follow the surface they sit on, including a theme toggled at runtime.
  function syncThemes() { scenes.forEach(scene => scene.syncTheme()); }
  new MutationObserver(syncThemes).observe(document.documentElement, { attributeFilter: ["data-theme"] });
  matchMedia("(prefers-color-scheme: dark)").addEventListener("change", syncThemes);

  window.airlockFabric = {
    mount,
    scenes,
    syncThemes,
    setRunning(value) { scenes.forEach(scene => scene.setRunning(value)); },
    setMode(value) { scenes.forEach(scene => scene.setMode(value)); },
    get available() { return scenes.some(scene => scene.available); },
  };

  document.querySelectorAll("[data-fabric]").forEach(host => {
    mount(host, {
      form: host.dataset.fabric,
      gain: host.dataset.fabricGain ? Number(host.dataset.fabricGain) : undefined,
      cold: parseTint(host.dataset.fabricCold) || undefined,
      warm: parseTint(host.dataset.fabricWarm) || undefined,
      theme: host.dataset.fabricTheme,
      pointer: host.dataset.fabricPointer !== "off",
    });
  });
})();
