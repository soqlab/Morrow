/**
 * The presentation layer for the Airlock Command tour and promo.
 *
 * Injected into the console page as an init script. It draws everything that
 * is *about* the product rather than part of it: scene cards, kinetic
 * narration, callouts anchored to real elements, count-ups, a cursor, and the
 * shot-to-shot transitions.
 *
 * It holds no clock of its own. The renderer calls `__ov.step(f)` once per
 * captured frame and every property is a pure function of `f`, so the overlay
 * is frame-exact no matter how long a frame took to render. The product's own
 * animation runs underneath on Chrome's virtual clock, which the renderer
 * advances by exactly one frame between screenshots.
 *
 * The root is attached to <html>, beside <body>, so nothing the page does to
 * body layout can move it and nothing it does can move the page.
 */
(() => {
  "use strict";
  if (window.__ov) return;

  const NS = "http://www.w3.org/2000/svg";
  const FPS = 60;
  // 1920x1080 with a 128px guard on every side: well inside the 5% title-safe
  // box, so nothing burned in can be cropped by a player or a re-frame.
  const SAFE = 128;

  const clamp01 = (t) => (t < 0 ? 0 : t > 1 ? 1 : t);
  const easeOut = (t) => 1 - Math.pow(1 - clamp01(t), 3);
  const easeIn = (t) => Math.pow(clamp01(t), 3);
  const easeInOut = (t) => { t = clamp01(t); return t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2; };
  const lerp = (a, b, t) => a + (b - a) * t;
  // Window of a frame index inside [a,b], 0 before and 1 after.
  const win = (f, a, b) => clamp01((f - a) / Math.max(1, b - a));

  let root = null;
  const L = {};            // named layers
  // A film that captures through a moving, cropped clip rectangle needs its
  // type further in than the frame's own guard: the crop travels, so the
  // overlay's left edge can end up outside it. `plan.inset` is the guard that
  // film wants, in the page's CSS pixels.
  let inset = null;
  let plan = null;
  let restore = [];        // product DOM text this overlay rewrote

  const CSS = `
#__ov, #__ov * { box-sizing: border-box; margin: 0; padding: 0; }
#__ov, #__ov * {
  text-transform: none; font-style: normal; text-decoration: none; font-variant: normal;
  letter-spacing: normal; text-align: inherit; float: none; position: static;
  border: 0; background: none; box-shadow: none; opacity: 1; visibility: visible;
  animation: none; transition: none; filter: none; mix-blend-mode: normal; }
#__ov {
  position: fixed; inset: 0; width: 100vw; height: 100vh;
  pointer-events: none; z-index: 2147483000;
  font-family: "IBM Plex Sans", system-ui, sans-serif;
  -webkit-font-smoothing: antialiased; text-rendering: geometricPrecision;
  contain: strict;
}
#__ov .ly { position: absolute; inset: 0; }

/* ---- transition ---- */
#__ovPrev { position: absolute; inset: 0; background-size: 100% 100%; background-position: 0 0; will-change: clip-path, transform, opacity; }
#__ovPrevShade { position: absolute; inset: 0; background: #05070B; opacity: 0; }

/* ---- scene card ---- */
#__ovScrim { position: absolute; inset: 0; background:
   radial-gradient(120% 90% at 50% 45%, rgba(10,14,21,.80) 0%, rgba(5,7,11,.94) 62%, #05070B 100%); opacity: 0; }
#__ovCard { position: absolute; left: ${SAFE}px; right: ${SAFE}px; top: 50%; transform: translateY(-50%); }
#__ovCard .kick {
  font-family: "IBM Plex Mono", ui-monospace, monospace; font-size: 24px; font-weight: 500;
  letter-spacing: .34em; text-transform: uppercase; color: #B6ABFF; margin-bottom: 26px; }
#__ovCard .big {
  font-family: "Archivo", system-ui, sans-serif; font-weight: 700; font-size: 132px; line-height: .98;
  letter-spacing: -.028em; color: #F4F6FA; white-space: pre-wrap; }
#__ovCard .big span { display: inline-block; will-change: transform, opacity, filter; }
#__ovCard .rule { height: 3px; background: linear-gradient(90deg,#7B6BFF,#D4913F); margin: 34px 0 0; width: 0; }
#__ovCard .sub { margin-top: 26px; font-size: 30px; line-height: 1.4; color: #A8B2C4; max-width: 1180px; }

/* ---- narration ---- */
#__ovNarr { position: absolute; }
#__ovNarr .scrim { position: absolute; inset: -44px -60px -38px -52px; border-radius: 4px; z-index: 0; }
#__ovNarr .bar { position: absolute; left: -26px; top: 4px; width: 4px; background: #7B6BFF; z-index: 2; }
#__ovNarr .body { position: relative; z-index: 1; }
#__ovNarr .ln {
  position: relative; font-size: 37px; line-height: 1.34; font-weight: 400; color: #EEF1F7;
  letter-spacing: -.004em; text-shadow: 0 2px 10px rgba(5,7,11,.85), 0 0 34px rgba(5,7,11,.7);
  will-change: transform, opacity, clip-path; }
#__ovNarr .ln em { font-style: normal; font-weight: 600; color: #B6ABFF; }
#__ovNarr .ln em.w { color: #E8AC63; }
#__ovNarr .ln em.g { color: #6FCBA5; }
#__ovNarr .ln b { font-weight: 600; color: #FFFFFF; }
#__ovNarr .eyebrow {
  font-family: "IBM Plex Mono", monospace; font-size: 17px; letter-spacing: .28em;
  text-transform: uppercase; color: #8A94A6; margin-bottom: 16px; }

/* ---- callouts ---- */
#__ovSvg { position: absolute; inset: 0; width: 100%; height: 100%; overflow: visible; }
#__ovSvg .co { fill: none; stroke: #9D90FF; stroke-width: 2.5; stroke-linecap: round; stroke-linejoin: round; }
#__ovSvg .co.warm { stroke: #E8AC63; }
#__ovSvg .co.good { stroke: #6FCBA5; }
#__ovSvg .glow { fill: none; stroke: rgba(123,107,255,.22); stroke-width: 9; stroke-linecap: round; }
#__ovLabels { position: absolute; inset: 0; }
#__ovLabels .chip {
  position: absolute; white-space: nowrap; font-family: "IBM Plex Mono", monospace;
  font-size: 19px; font-weight: 500; letter-spacing: .06em; color: #EEF1F7;
  background: rgba(10,14,21,.93); border: 1px solid rgba(123,107,255,.55);
  padding: 9px 15px; border-radius: 3px; box-shadow: 0 8px 28px rgba(0,0,0,.6);
  will-change: transform, opacity; }
#__ovLabels .chip.warm { border-color: rgba(212,145,63,.6); }
#__ovLabels .chip.good { border-color: rgba(79,181,139,.6); }
#__ovLabels .chip i { font-style: normal; color: #8A94A6; }

/* ---- chapter marker ---- */
#__ovChap { position: absolute; left: ${SAFE - 14}px; bottom: ${SAFE - 52}px; display: flex; align-items: center;
  gap: 14px; background: rgba(5,7,11,.86); padding: 8px 16px; border-radius: 3px; }
#__ovChap .n { font-family: "IBM Plex Mono", monospace; font-size: 16px; letter-spacing: .2em; color: #7B6BFF; }
#__ovChap .t { font-family: "IBM Plex Mono", monospace; font-size: 16px; letter-spacing: .2em;
  text-transform: uppercase; color: #8A94A6; }
#__ovChap .d { width: 44px; height: 1px; background: #2A3345; }

/* ---- cursor ---- */
#__ovCur { position: absolute; left: 0; top: 0; width: 26px; height: 32px; opacity: 0; will-change: transform, opacity; }
#__ovRing { position: absolute; left: 0; top: 0; width: 20px; height: 20px; margin: -10px 0 0 -10px;
  border: 2px solid #9D90FF; border-radius: 50%; opacity: 0; will-change: transform, opacity; }

/* ---- progress ---- */
#__ovProg { position: absolute; left: 0; right: 0; bottom: 0; height: 3px; background: rgba(26,33,48,.55); }
#__ovProg i { display: block; height: 100%; width: 0; background: linear-gradient(90deg,#7B6BFF,#9D90FF); }

/* ---- vignette: a permanent, very slight darkening of the corners, so the
   frame reads as one graded piece rather than a screen recording ---- */
#__ovVig { position: absolute; inset: 0; opacity: 0; pointer-events: none;
  background: radial-gradient(118% 92% at 50% 46%, rgba(5,7,11,0) 44%, rgba(5,7,11,.30) 78%, rgba(5,7,11,.62) 100%); }

/* ---- promo type ---- */
#__ovBig { position: absolute; left: ${SAFE}px; right: ${SAFE}px; top: 0; height: 100%;
  padding: ${SAFE}px 0 ${SAFE + 18}px; display: flex; flex-direction: column; justify-content: center;
  perspective: 1400px; perspective-origin: 34% 50%; transform-style: preserve-3d; }
#__ovBig .l {
  font-family: "Archivo", system-ui, sans-serif; font-weight: 700; font-size: 118px; line-height: 1.02;
  letter-spacing: -.03em; color: #F4F6FA; will-change: transform, opacity, clip-path; }
#__ovBig .l.sm { font-size: 66px; letter-spacing: -.022em; }
#__ovBig .l.xl { font-family: "Archivo", system-ui, sans-serif; font-size: 240px; font-weight: 700;
  letter-spacing: -.045em; line-height: .92; }
#__ovBig .l.md { font-size: 86px; letter-spacing: -.026em; }
#__ovBig .l.tag { font-family: "IBM Plex Sans", system-ui, sans-serif; font-size: 38px; font-weight: 400;
  letter-spacing: 0; color: #A8B2C4; line-height: 1.35; }
#__ovBig .l.mono { font-family: "IBM Plex Mono", monospace; font-size: 44px; font-weight: 500;
  letter-spacing: .16em; text-transform: uppercase; color: #9D90FF; }
#__ovBig .l .hl { color: #D4913F; }
#__ovBig .l .hlg { color: #4FB58B; }
#__ovBig .l .hli { color: #9D90FF; }
#__ovBig .l { transform-style: preserve-3d; backface-visibility: hidden; }
/* A plate that sits behind a figure and softens the product under it, so the
   number reads at a different depth from the screen it came from. */
#__ovBig .plate {
  display: inline-block; padding: 10px 26px 14px; border-radius: 3px;
  background: linear-gradient(180deg, rgba(10,14,21,.90), rgba(5,7,11,.82));
  box-shadow: 0 26px 70px rgba(0,0,0,.66), inset 0 1px 0 rgba(123,107,255,.22); }
`;

  function el(tag, id, parent, cls) {
    const e = document.createElement(tag);
    if (id) e.id = id;
    if (cls) e.className = cls;
    (parent || root).appendChild(e);
    return e;
  }

  let focusEl = null;

  function mount() {
    if (root && root.isConnected) return;
    const style = document.createElement("style");
    style.id = "__ovStyle";
    style.textContent = CSS;
    document.documentElement.appendChild(style);
    focusEl = document.createElement("div");
    focusEl.id = "__ovFocus";
    focusEl.style.cssText = "position:fixed;inset:0;pointer-events:none;z-index:2147482999;";
    document.documentElement.appendChild(focusEl);
    root = document.createElement("div");
    root.id = "__ov";
    document.documentElement.appendChild(root);

    L.prev = el("div", "__ovPrev", root);
    L.prevShade = el("div", "__ovPrevShade", root);
    L.scrim = el("div", "__ovScrim", root);
    L.card = el("div", "__ovCard", root);
    L.cardKick = el("div", null, L.card, "kick");
    L.cardBig = el("div", null, L.card, "big");
    L.cardRule = el("div", null, L.card, "rule");
    L.cardSub = el("div", null, L.card, "sub");
    L.svg = document.createElementNS(NS, "svg");
    L.svg.id = "__ovSvg";
    L.svg.setAttribute("viewBox", "0 0 1920 1080");
    root.appendChild(L.svg);
    L.labels = el("div", "__ovLabels", root);
    L.narr = el("div", "__ovNarr", root);
    L.narrScrim = el("div", null, L.narr, "scrim");
    L.narrBar = el("div", null, L.narr, "bar");
    L.narrBody = el("div", null, L.narr, "body");
    L.big = el("div", "__ovBig", root);
    L.chap = el("div", "__ovChap", root);
    L.chapN = el("span", null, L.chap, "n");
    L.chapD = el("span", null, L.chap, "d");
    L.chapT = el("span", null, L.chap, "t");
    L.cur = el("div", "__ovCur", root);
    L.cur.innerHTML = '<svg width="26" height="32" viewBox="0 0 26 32">' +
      '<path d="M2 1 L2 24 L8.2 18.6 L12.2 27.6 L16.4 25.6 L12.4 17 L20.6 16.4 Z" ' +
      'fill="#F4F6FA" stroke="#0A0E15" stroke-width="1.6" stroke-linejoin="round"/></svg>';
    L.ring = el("div", "__ovRing", root);
    L.prog = el("div", "__ovProg", root);
    L.progI = el("i", null, L.prog);
    L.vig = el("div", "__ovVig", root);
    hideAll();
  }

  function hideAll() {
    L.prev.style.display = "none";
    L.prevShade.style.opacity = "0";
    L.scrim.style.opacity = "0";
    if (focusEl) { focusEl.style.backdropFilter = "none"; focusEl.style.webkitBackdropFilter = "none"; }
    L.card.style.display = "none";
    L.narr.style.display = "none";
    L.big.style.display = "none";
    L.chap.style.display = "none";
    L.cur.style.opacity = "0";
    L.ring.style.opacity = "0";
    L.prog.style.display = "none";
    L.svg.textContent = "";
    L.labels.textContent = "";
    // L.vig is deliberately untouched: it belongs to the film, not the shot.
  }

  /* --------------------------------------------------------------- measuring
     Rects are read in CSS pixels relative to the viewport, which is exactly
     the coordinate space the overlay draws in. */
  function rect(sel, opts) {
    const o = opts || {};
    let e = null;
    if (o.text) {
      for (const c of document.querySelectorAll(sel)) {
        if ((c.textContent || "").replace(/\s+/g, " ").includes(o.text)) { e = c; break; }
      }
    } else {
      const all = document.querySelectorAll(sel);
      e = all[o.nth || 0] || null;
    }
    if (!e) return null;
    const r = e.getBoundingClientRect();
    if (!r.width || !r.height) return null;
    return { x: r.x, y: r.y, w: r.width, h: r.height };
  }

  /* --------------------------------------------------------------- count-ups
     The number the product already shows is rewritten in place while it counts
     to its own value, then restored. The value is never invented: the target
     is whatever the element was rendering. */
  function findNumberNode(e) {
    const walk = document.createTreeWalker(e, NodeFilter.SHOW_TEXT);
    let n;
    while ((n = walk.nextNode())) {
      if (/[0-9]/.test(n.nodeValue) && n.nodeValue.trim().length <= 24) return n;
    }
    return null;
  }

  function prepCount(item) {
    const e = document.querySelectorAll(item.sel)[item.nth || 0];
    if (!e) return null;
    const node = findNumberNode(e);
    if (!node) return null;
    const raw = node.nodeValue;
    const m = /(-?[\d][\d,\s]*(?:\.\d+)?)/.exec(raw);
    if (!m) return null;
    const target = parseFloat(m[1].replace(/[,\s]/g, ""));
    if (!isFinite(target)) return null;
    restore.push([node, raw]);
    const dec = (m[1].split(".")[1] || "").length;
    const grouped = m[1].includes(",");
    // A count-up is for a quantity arriving, not for a year. A bare four-digit
    // year rising from nothing reads as a broken number, so it starts just
    // short of itself unless the caller says otherwise.
    let from = item.from;
    if (from == null) {
      from = (!dec && !grouped && target >= 1900 && target <= 2200) ? target - 4 : 0;
    }
    return { node, raw, head: raw.slice(0, m.index), tail: raw.slice(m.index + m[1].length),
             target, from, dec, grouped };
  }

  function fmt(v, dec, grouped) {
    let s = dec ? v.toFixed(dec) : String(Math.round(v));
    if (grouped) {
      const p = s.split(".");
      p[0] = p[0].replace(/\B(?=(\d{3})+(?!\d))/g, ",");
      s = p.join(".");
    }
    return s;
  }

  /* ------------------------------------------------------------- transitions
     The outgoing frame is a still of the shot just finished; the incoming
     picture underneath it is live and animating the whole time. */
  function drawTrans(it, f) {
    const t = win(f, it.a, it.b);
    const p = L.prev;
    p.style.display = "block";
    p.style.opacity = "1";
    p.style.transform = "none";
    p.style.clipPath = "none";
    p.style.filter = "none";
    const e = easeInOut(t);
    switch (it.kind) {
      case "wipeleft":   p.style.clipPath = `inset(0 0 0 ${(e * 100).toFixed(3)}%)`; break;
      case "wiperight":  p.style.clipPath = `inset(0 ${(e * 100).toFixed(3)}% 0 0)`; break;
      case "wipeup":     p.style.clipPath = `inset(${(e * 100).toFixed(3)}% 0 0 0)`; break;
      case "wipedown":   p.style.clipPath = `inset(0 0 ${(e * 100).toFixed(3)}% 0)`; break;
      case "push":
        p.style.transform = `translateX(${(-e * 100).toFixed(3)}%)`;
        p.style.filter = `brightness(${(1 - 0.25 * e).toFixed(3)})`;
        break;
      case "pushup":
        p.style.transform = `translateY(${(-e * 100).toFixed(3)}%)`;
        p.style.filter = `brightness(${(1 - 0.25 * e).toFixed(3)})`;
        break;
      case "iris": {
        const r = lerp(76, 0, e);
        p.style.clipPath = `circle(${r.toFixed(2)}% at 50% 48%)`;
        p.style.filter = `brightness(${(1 - 0.18 * e).toFixed(3)})`;
        break;
      }
      case "bars": {
        const n = 7, parts = [];
        for (let i = 0; i < n; i++) {
          const k = clamp01((t - i * 0.055) / 0.62);
          const cut = easeInOut(k) * 100;
          const x0 = (i * 100) / n, x1 = ((i + 1) * 100) / n;
          parts.push(`polygon(${x0}% ${cut}%, ${x1}% ${cut}%, ${x1}% 100%, ${x0}% 100%)`);
        }
        // clip-path takes one shape, so bars are drawn as a single polygon list
        // via an SVG-free approximation: a repeating linear mask.
        p.style.clipPath = "none";
        p.style.webkitMaskImage = parts.map(() => "linear-gradient(#000,#000)").join(",");
        p.style.webkitMaskRepeat = "no-repeat";
        p.style.webkitMaskPosition = parts.map((_, i) => `${(i * 1920) / n}px ${(easeInOut(clamp01((t - i * 0.055) / 0.62)) * 1080).toFixed(1)}px`).join(",");
        p.style.webkitMaskSize = parts.map(() => `${1920 / n + 1}px 1080px`).join(",");
        break;
      }
      case "fade":
      default:
        p.style.opacity = (1 - e).toFixed(4);
    }
    if (it.kind !== "bars") { p.style.webkitMaskImage = "none"; }
    if (t >= 1) p.style.display = "none";
  }

  /* -------------------------------------------------------------- scene card */
  function drawCard(it, f) {
    L.card.style.display = "block";
    const inT = win(f, it.a, it.a + (it.inF || 26));
    const outA = it.b - (it.outF || 30);
    const outT = win(f, outA, it.b);
    // The scrim sits at full strength while the words are up and clears to
    // nothing as they leave, so the screen behind resolves through the card.
    // `scrim: null` means a standalone scrim item owns the darkening, so the
    // card must not ease it up from nothing — that showed as a flash of bright
    // UI in the middle of the wipe into the end card.
    if (it.scrim !== null) {
      const s = (it.scrim == null ? 0.96 : it.scrim) * (1 - easeIn(outT)) * easeOut(win(f, it.a, it.a + 10));
      L.scrim.style.opacity = s.toFixed(4);
    }

    if (L.cardBig.dataset.txt !== it.big) {
      L.cardBig.dataset.txt = it.big;
      L.cardBig.innerHTML = it.big.split("").map((c) =>
        c === " " ? "<span>&nbsp;</span>" : c === "\n" ? "<br>" : `<span>${c.replace(/&/g, "&amp;").replace(/</g, "&lt;")}</span>`).join("");
    }
    const spans = L.cardBig.children;
    for (let i = 0; i < spans.length; i++) {
      const k = clamp01((inT * (spans.length + 9) - i) / 9);
      const o = easeOut(k);
      const dy = lerp(46, 0, o);
      const so = easeIn(outT);
      spans[i].style.opacity = (o * (1 - so)).toFixed(4);
      spans[i].style.transform = `translateY(${(dy - so * 22).toFixed(2)}px)`;
      spans[i].style.filter = so > 0 ? `blur(${(so * 9).toFixed(2)}px)` : "none";
    }
    L.cardKick.textContent = it.kick || "";
    L.cardKick.style.opacity = (easeOut(win(f, it.a, it.a + 14)) * (1 - easeIn(outT))).toFixed(4);
    L.cardKick.style.transform = `translateX(${lerp(-26, 0, easeOut(win(f, it.a, it.a + 18))).toFixed(2)}px)`;
    L.cardRule.style.width = `${(easeInOut(win(f, it.a + 8, it.a + 40)) * (it.ruleW || 320) * (1 - easeIn(outT))).toFixed(1)}px`;
    L.cardSub.textContent = it.sub || "";
    L.cardSub.style.opacity = (easeOut(win(f, it.a + 16, it.a + 34)) * (1 - easeIn(outT))).toFixed(4);
    L.cardSub.style.transform = `translateY(${lerp(16, 0, easeOut(win(f, it.a + 16, it.a + 34))).toFixed(2)}px)`;
    if (f >= it.b) {
      L.card.style.display = "none";
      if (it.scrim !== null) L.scrim.style.opacity = "0";
    }
  }

  /* -------------------------------------------------------------- narration
     Lines arrive one after another and leave together. Nothing sits at the
     bottom of the frame for the whole film: `pos` moves the block to whichever
     corner the shot is not using. */
  const POS = {
    bl: { left: SAFE + 26, bottom: SAFE + 64, right: "auto", top: "auto" },
    tl: { left: SAFE + 26, top: SAFE + 6, right: "auto", bottom: "auto" },
    br: { right: SAFE + 26, bottom: SAFE + 64, left: "auto", top: "auto" },
    tr: { right: SAFE + 26, top: SAFE + 6, left: "auto", bottom: "auto" },
    ml: { left: SAFE + 26, top: 470, right: "auto", bottom: "auto" },
    c:  { left: SAFE + 26, top: 430, right: "auto", bottom: "auto" },
  };

  function drawNarr(it, f) {
    L.narr.style.display = "block";
    const p = POS[it.pos || "bl"];
    for (const k of ["left", "right", "top", "bottom"]) {
      L.narr.style[k] = typeof p[k] === "number" ? p[k] + "px" : p[k];
    }
    L.narr.style.width = (it.w || 1100) + "px";
    L.narr.style.textAlign = it.align || "left";

    const key = (it.eyebrow || "") + "|" + it.lines.join("|");
    if (L.narrBody.dataset.k !== key) {
      L.narrBody.dataset.k = key;
      L.narrBody.innerHTML =
        (it.eyebrow ? `<div class="eyebrow">${it.eyebrow}</div>` : "") +
        it.lines.map((s) => `<div class="ln">${s}</div>`).join("");
    }
    const kids = [...L.narrBody.children];
    const lines = kids.filter((k) => k.className === "ln");
    const eye = kids.find((k) => k.className === "eyebrow");
    const outA = it.b - (it.outF || 16);
    const outT = easeIn(win(f, outA, it.b));

    if (eye) {
      const t = easeOut(win(f, it.a, it.a + 12));
      eye.style.opacity = (t * (1 - outT)).toFixed(4);
      eye.style.transform = `translateX(${lerp(-18, 0, t).toFixed(2)}px)`;
    }
    lines.forEach((ln, i) => {
      const a = it.a + i * (it.stagger == null ? 7 : it.stagger);
      const t = easeOut(win(f, a, a + 17));
      ln.style.opacity = (t * (1 - outT)).toFixed(4);
      ln.style.transform = `translateY(${(lerp(22, 0, t) - outT * 14).toFixed(2)}px)`;
      // A reveal that uncovers the words from the left rather than fading them.
      ln.style.clipPath = t < 1 ? `inset(-14% ${((1 - t) * 100).toFixed(2)}% -22% -4%)` : "none";
    });
    // A local scrim only, sized to the text, never a bar across the frame.
    const sc = easeOut(win(f, it.a, it.a + 14)) * (1 - outT);
    const dir = (it.pos || "bl").startsWith("t") ? "180deg" : "0deg";
    L.narrScrim.style.background =
      `linear-gradient(${dir}, rgba(5,7,11,${(0.86 * sc).toFixed(3)}) 0%, rgba(5,7,11,${(0.66 * sc).toFixed(3)}) 58%, rgba(5,7,11,0) 100%)`;
    L.narrScrim.style.webkitMaskImage = (it.pos || "bl").startsWith("t") || (it.pos || "bl").endsWith("r")
      ? "linear-gradient(to left, #000 58%, transparent 100%)"
      : "linear-gradient(to right, #000 58%, transparent 100%)";
    const bh = L.narrBody.getBoundingClientRect().height || 90;
    L.narrBar.style.height = `${(bh * easeOut(win(f, it.a, it.a + 22)) * (1 - outT)).toFixed(1)}px`;
    L.narrBar.style.opacity = (1 - outT).toFixed(3);
    if (f >= it.b) L.narr.style.display = "none";
  }

  /* --------------------------------------------------------------- callouts */
  function svgEl(tag, attrs, cls) {
    const e = document.createElementNS(NS, tag);
    for (const k in attrs) e.setAttribute(k, attrs[k]);
    if (cls) e.setAttribute("class", cls);
    return e;
  }

  function calloutPath(it) {
    const r = it.rect, pad = it.pad == null ? 10 : it.pad;
    const x = r.x - pad, y = r.y - pad, w = r.w + pad * 2, h = r.h + pad * 2;
    if (it.shape === "ring") {
      const cx = r.x + r.w / 2, cy = r.y + r.h / 2;
      const rad = Math.max(w, h) / 2 + 6;
      return `M ${cx} ${cy - rad} A ${rad} ${rad} 0 1 1 ${cx - 0.01} ${cy - rad} Z`;
    }
    if (it.shape === "bracket") {
      const c = Math.min(26, w / 3, h / 3);
      return `M ${x + c} ${y} L ${x} ${y} L ${x} ${y + c} M ${x + w - c} ${y} L ${x + w} ${y} L ${x + w} ${y + c} ` +
             `M ${x + c} ${y + h} L ${x} ${y + h} L ${x} ${y + h - c} M ${x + w - c} ${y + h} L ${x + w} ${y + h} L ${x + w} ${y + h - c}`;
    }
    if (it.shape === "underline") {
      return `M ${x} ${y + h} L ${x + w} ${y + h}`;
    }
    const rr = it.r == null ? 4 : it.r;
    return `M ${x + rr} ${y} H ${x + w - rr} Q ${x + w} ${y} ${x + w} ${y + rr} V ${y + h - rr} ` +
           `Q ${x + w} ${y + h} ${x + w - rr} ${y + h} H ${x + rr} Q ${x} ${y + h} ${x} ${y + h - rr} ` +
           `V ${y + rr} Q ${x} ${y} ${x + rr} ${y} Z`;
  }

  function drawCallout(it, f) {
    // A callout anchored by selector re-measures every frame, so it stays on
    // its element through a scroll instead of sliding off it.
    if (it.sel) {
      const live = rect(it.sel, it);
      if (live) it.rect = live;
      else if (!it.rect) return;
    }
    if (!it.rect) return;
    if (!it._p) {
      const d = calloutPath(it);
      it._glow = svgEl("path", { d }, "glow");
      it._p = svgEl("path", { d }, "co" + (it.tone ? " " + it.tone : ""));
      L.svg.appendChild(it._glow);
      L.svg.appendChild(it._p);
      const len = it._p.getTotalLength();
      it._len = len;
      it._p.style.strokeDasharray = len;
      it._glow.style.strokeDasharray = len;
      if (it.label) {
        it._chip = document.createElement("div");
        it._chip.className = "chip" + (it.tone ? " " + it.tone : "");
        it._chip.innerHTML = it.label;
        L.labels.appendChild(it._chip);
      }
      // A leader line from the chip to the shape, when the chip sits away.
      if (it.leader) {
        it._lead = svgEl("path", { d: `M ${it.leader[0]} ${it.leader[1]} L ${it.leader[2]} ${it.leader[3]}` }, "co" + (it.tone ? " " + it.tone : ""));
        it._lead.style.strokeWidth = "1.6";
        const ll = it._lead.getTotalLength();
        it._lead.style.strokeDasharray = ll;
        it._leadLen = ll;
        L.svg.insertBefore(it._lead, it._p);
      }
    }
    if (it.sel) {
      const d = calloutPath(it);
      it._p.setAttribute("d", d);
      it._glow.setAttribute("d", d);
      it._len = it._p.getTotalLength();
      it._p.style.strokeDasharray = it._len;
      it._glow.style.strokeDasharray = it._len;
    }
    const drawT = easeInOut(win(f, it.a, it.a + (it.drawF || 24)));
    const outT = easeIn(win(f, it.b - (it.outF || 14), it.b));
    const vis = 1 - outT;
    it._p.style.strokeDashoffset = (it._len * (1 - drawT)).toFixed(2);
    it._p.style.opacity = vis.toFixed(3);
    it._glow.style.strokeDashoffset = (it._len * (1 - drawT)).toFixed(2);
    it._glow.style.opacity = (vis * 0.9).toFixed(3);
    if (it._lead) {
      const lt = easeInOut(win(f, it.a + 10, it.a + 30));
      it._lead.style.strokeDashoffset = (it._leadLen * (1 - lt)).toFixed(2);
      it._lead.style.opacity = (vis * 0.85).toFixed(3);
    }
    if (it._chip) {
      const ct = easeOut(win(f, it.a + (it.chipDelay == null ? 14 : it.chipDelay), it.a + (it.chipDelay == null ? 14 : it.chipDelay) + 16));
      it._chip.style.opacity = (ct * vis).toFixed(3);
      const cw = it._chip.offsetWidth, ch = it._chip.offsetHeight;
      const r = it.rect;
      let cx, cy;
      const side = it.side || "below";
      if (side === "below") { cx = r.x + r.w / 2 - cw / 2; cy = r.y + r.h + 22; }
      else if (side === "above") { cx = r.x + r.w / 2 - cw / 2; cy = r.y - ch - 22; }
      else if (side === "left") { cx = r.x - cw - 24; cy = r.y + r.h / 2 - ch / 2; }
      else { cx = r.x + r.w + 24; cy = r.y + r.h / 2 - ch / 2; }
      if (it.at) { cx = it.at[0]; cy = it.at[1]; }
      const gx = inset ? inset[0] : SAFE;
      const gy = inset ? inset[1] : SAFE - 24;
      cx = Math.max(gx, Math.min(cx, 1920 - gx - cw));
      cy = Math.max(gy, Math.min(cy, 1080 - gy - ch));
      it._chip.style.left = cx.toFixed(1) + "px";
      it._chip.style.top = cy.toFixed(1) + "px";
      it._chip.style.transform = `translateY(${lerp(10, 0, ct).toFixed(2)}px)`;
    }
  }

  /* ----------------------------------------------------------------- cursor
     Eased travel between waypoints, with a ring that expands where a click
     lands, so the interface reads as operated rather than photographed. */
  function drawCursor(it, f) {
    const t = clamp01((f - it.a) / Math.max(1, it.b - it.a));
    const pts = it.path;
    const e = easeInOut(t);
    const seg = Math.min(pts.length - 2, Math.floor(e * (pts.length - 1)));
    const local = e * (pts.length - 1) - seg;
    const x = lerp(pts[seg][0], pts[seg + 1][0], local);
    const y = lerp(pts[seg][1], pts[seg + 1][1], local);
    const vis = easeOut(win(f, it.a, it.a + 10)) * (1 - easeIn(win(f, it.b - 10, it.b)));
    L.cur.style.opacity = vis.toFixed(3);
    L.cur.style.transform = `translate(${x.toFixed(2)}px, ${y.toFixed(2)}px)`;
    if (it.click != null) {
      const ct = win(f, it.click, it.click + 22);
      if (f >= it.click && f <= it.click + 24) {
        const s = lerp(0.3, 3.4, easeOut(ct));
        L.ring.style.opacity = ((1 - ct) * 0.9).toFixed(3);
        L.ring.style.transform = `translate(${x.toFixed(2)}px, ${y.toFixed(2)}px) scale(${s.toFixed(3)})`;
      } else {
        L.ring.style.opacity = "0";
      }
      // A small press on the arrow itself at the moment of the click.
      if (f >= it.click - 3 && f <= it.click + 6) {
        L.cur.style.transform += " scale(.86)";
      }
    }
    if (f >= it.b) { L.cur.style.opacity = "0"; L.ring.style.opacity = "0"; }
  }

  /* ------------------------------------------------------------ promo type */
  function drawBig(it, f) {
    L.big.style.display = "flex";
    L.big.style.textAlign = it.align || "left";
    L.big.style.justifyContent = it.justify || "center";
    const key = it.lines.join("|") + (it.cls || "");
    if (L.big.dataset.k !== key) {
      L.big.dataset.k = key;
      L.big.innerHTML = it.lines.map((s, i) =>
        `<div class="l ${(it.cls && it.cls[i]) || ""}">${s}</div>`).join("");
    }
    const kids = [...L.big.children];
    const outA = it.b - (it.outF || 12);
    const outT = easeIn(win(f, outA, it.b));
    kids.forEach((k, i) => {
      const a = it.a + i * (it.stagger == null ? 5 : it.stagger);
      const t = easeOut(win(f, a, a + (it.inF || 14)));
      k.style.opacity = (t * (1 - outT)).toFixed(3);
      const mode = it.mode || "rise";
      if (mode === "rise") {
        k.style.transform = `translateY(${(lerp(40, 0, t) + outT * -24).toFixed(2)}px)`;
        k.style.clipPath = t < 1 ? `inset(-12% 0 ${((1 - t) * 108).toFixed(1)}% 0)` : "none";
      } else if (mode === "wipe") {
        k.style.transform = "none";
        k.style.clipPath = t < 1 ? `inset(-12% ${((1 - t) * 100).toFixed(1)}% -14% 0)` : "none";
      } else if (mode === "scale") {
        k.style.transform = `scale(${lerp(1.14, 1, t).toFixed(4)})`;
        k.style.clipPath = "none";
      } else if (mode === "depth") {
        // Arrives out of the screen: a small rotation about Y and a push in z,
        // so the words have somewhere to come from.
        k.style.transform =
          `translate3d(0, ${lerp(26, 0, t).toFixed(2)}px, ${lerp(-460, 0, t).toFixed(1)}px) ` +
          `rotateY(${lerp(-13, 0, t).toFixed(3)}deg)`;
        k.style.clipPath = "none";
      }
    });
    if (f >= it.b) L.big.style.display = "none";
  }

  /* ---------------------------------------------------------------- chapter */
  function drawChap(it, f) {
    L.chap.style.display = "flex";
    L.chapN.textContent = it.n;
    L.chapT.textContent = it.label;
    const t = easeOut(win(f, it.a, it.a + 20));
    const outT = easeIn(win(f, it.b - 18, it.b));
    L.chap.style.opacity = (t * (1 - outT) * 0.95).toFixed(3);
    L.chapD.style.width = `${(44 * t).toFixed(1)}px`;
    L.chap.style.transform = `translateX(${lerp(-14, 0, t).toFixed(2)}px)`;
    if (f >= it.b) L.chap.style.display = "none";
  }

  /* -------------------------------------------------------------------- API */
  function begin(p) {
    mount();
    endRestore();
    hideAll();
    plan = JSON.parse(JSON.stringify(p));
    inset = plan.inset || null;
    if (inset) {
      const [ix, iy] = inset;
      L.big.style.left = ix + "px";
      L.big.style.right = ix + "px";
      L.big.style.paddingTop = iy + "px";
      L.big.style.paddingBottom = (iy + 16) + "px";
      L.card.style.left = ix + "px";
      L.card.style.right = ix + "px";
      L.chap.style.left = ix + "px";
    }
    for (const it of plan.items) {
      if (it.k === "count") it._c = prepCount(it);
    }
    if (plan.prog) { L.prog.style.display = "block"; }
    return true;
  }

  function endRestore() {
    for (const [node, raw] of restore) { try { node.nodeValue = raw; } catch (e) { /* gone */ } }
    restore = [];
  }

  /* The renderer drifts the capture rectangle half a CSS pixel a frame. Passing
     that offset in here and moving the type the other way puts the words at a
     different depth from the product: the screen slides one way behind them
     while they hold, which is parallax rather than a sticker on the glass. */
  function step(f, dx, dy) {
    if (!plan) return;
    if (dx != null) {
      const k = plan.parallax == null ? 1.6 : plan.parallax;
      const t = `translate3d(${(dx * k).toFixed(3)}px, ${(dy * k).toFixed(3)}px, 0)`;
      L.big.style.transform = t;
      L.card.style.transform = `translateY(-50%) ${t}`;
      L.narr.style.transform = t;
    }
    for (const it of plan.items) {
      if (f < it.a || f > it.b + 2) {
        if (it.k === "count" && it._c && f > it.b) it._c.node.nodeValue = it._c.raw;
        continue;
      }
      switch (it.k) {
        case "trans": drawTrans(it, f); break;
        case "card": drawCard(it, f); break;
        case "narr": drawNarr(it, f); break;
        case "call": drawCallout(it, f); break;
        case "cursor": drawCursor(it, f); break;
        case "big": drawBig(it, f); break;
        case "chap": drawChap(it, f); break;
        case "scrim": {
          const up = easeOut(win(f, it.a, it.a + (it.inF || 14)));
          const down = easeIn(win(f, it.b - (it.outF || 14), it.b));
          L.scrim.style.opacity = ((it.level == null ? 0.9 : it.level) * up * (1 - down)).toFixed(4);
          // Rack focus: the scrim also carries a backdrop blur, so the product
          // behind the words can sit out of focus and come sharp as the beat
          // turns to what it does. `blur` may be a pair to ramp between.
          if (it.blur != null && focusEl) {
            const b0 = Array.isArray(it.blur) ? it.blur[0] : it.blur;
            const b1 = Array.isArray(it.blur) ? it.blur[1] : it.blur;
            const bt = easeInOut(win(f, it.blurA == null ? it.a : it.blurA,
                                     it.blurB == null ? it.b : it.blurB));
            const px = lerp(b0, b1, bt);
            const css = px > 0.05 ? `blur(${px.toFixed(2)}px)` : "none";
            focusEl.style.backdropFilter = css;
            focusEl.style.webkitBackdropFilter = css;
          } else if (focusEl) {
            focusEl.style.backdropFilter = "none";
            focusEl.style.webkitBackdropFilter = "none";
          }
          L.scrim.style.background =
            it.grad === "bottom"
              ? "linear-gradient(0deg, rgba(5,7,11,.97) 0%, rgba(5,7,11,.80) 34%, rgba(5,7,11,.10) 66%, rgba(5,7,11,0) 100%)"
              : it.flat
                ? "#05070B"
                : "radial-gradient(120% 90% at 50% 45%, rgba(10,14,21,.80) 0%, rgba(5,7,11,.94) 62%, #05070B 100%)";
          break;
        }
        case "count": {
          const c = it._c;
          if (!c) break;
          const t = easeOut(win(f, it.a, it.b));
          c.node.nodeValue = c.head + fmt(c.from + (c.target - c.from) * t, c.dec, c.grouped) + c.tail;
          break;
        }
      }
    }
    if (plan.prog) {
      L.progI.style.width = (plan.prog[0] + (plan.prog[1] - plan.prog[0]) * (f / Math.max(1, plan.dur))) * 100 + "%";
    }
  }

  function setPrev(url) {
    mount();
    L.prev.style.backgroundImage = `url("${url}")`;
    L.prev.style.display = "block";
    L.prev.style.opacity = "1";
    L.prev.style.clipPath = "none";
    L.prev.style.transform = "none";
    L.prev.style.webkitMaskImage = "none";
  }

  /* The transition image is a 3840x2160 JPEG held as a CSS background, which
     Chrome keeps as a decoded bitmap of about 33 MB. Forty of those over a
     nine-minute render is what eventually wedged a screenshot, so it is
     dropped the moment the shot that used it is finished. */
  function clear() {
    endRestore();
    hideAll();
    L.prev.style.backgroundImage = "none";
    plan = null;
  }

  /** The vignette is set once for a whole film and left alone. */
  function vignette(level) { mount(); L.vig.style.opacity = String(level == null ? 1 : level); }

  window.__ov = { mount, begin, step, rect, setPrev, clear, vignette, SAFE, FPS };
})();
