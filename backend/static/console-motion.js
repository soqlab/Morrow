(() => {
  "use strict";
  /* ==========================================================================
     Console motion.

     Two effects that mutate text, and both are deliberately narrow:

       scramble  runs only on decorative mono labels. It never touches the view
                 title, metric values or any copy a reader has to trust, because
                 mid-flight those elements would briefly read as nonsense.
       countUp   runs only where the element's whole text is a number. A value
                 like "—" or "No runs" is left exactly as rendered rather than
                 animated to zero.

     Both stop dead under prefers-reduced-motion and under the workspace pause
     control, which is the same preference the generative field obeys.
     ========================================================================== */

  const reduced = matchMedia("(prefers-reduced-motion: reduce)");
  const paused = () => document.body.dataset.motion === "paused";
  const still = () => reduced.matches || paused();
  /* Both effects rewrite text on every step, and each rewrite lays the page out
     again. Scrolling is when labels and values come into view, so an effect
     that would start while the page is still moving shows its final text
     instead of competing with the scroll. */
  let scrollAt = -Infinity;
  addEventListener("scroll", () => { scrollAt = performance.now(); }, { passive: true, capture: true });
  const scrolling = () => performance.now() - scrollAt < 200;

  /* ---------- cipher scramble on decorative labels ---------- */
  const GLYPHS = "0123456789ABCDEF#/\\<>+=*";
  // Only these. Anything carrying meaning a reader or a test depends on is out.
  const LABELS = ".leadEyebrow, .secHead h2, .overviewEyebrow > span:first-child";

  function scramble(el) {
    if (el.dataset.pnScrambled) return;
    el.dataset.pnScrambled = "1";
    const final = el.textContent;
    if (!final || final.length > 48 || scrolling()) return;
    const start = [...final].map(() => Math.floor(Math.random() * 8));
    let frame = 0;
    const step = () => {
      if (still()) { el.textContent = final; return; }
      let out = "", settled = 0;
      for (let i = 0; i < final.length; i++) {
        const ch = final[i];
        if (ch === " " || frame > start[i] + 6) { out += ch; settled++; }
        else if (frame > start[i]) out += GLYPHS[Math.floor(Math.random() * GLYPHS.length)];
        else out += " ";
      }
      el.textContent = out;
      frame++;
      if (settled < final.length) setTimeout(step, 32);
      else el.textContent = final;
    };
    step();
  }

  /* ---------- count-up on values that are purely numeric ---------- */
  const NUMERIC = /^([^\d\-+]*)(-?[\d,]+(?:\.\d+)?)([^\d]*)$/;

  function countUp(el) {
    if (el.dataset.pnCounted) return;
    const text = el.textContent.trim();
    if (scrolling()) { el.dataset.pnCounted = "1"; return; }
    const match = NUMERIC.exec(text);
    if (!match) { el.dataset.pnCounted = "1"; return; }   // "—", "No runs": leave alone
    const target = Number(match[2].replace(/,/g, ""));
    if (!Number.isFinite(target) || Math.abs(target) < 2) { el.dataset.pnCounted = "1"; return; }
    el.dataset.pnCounted = "1";
    const [, prefix, digits, suffix] = match;
    const decimals = (digits.split(".")[1] || "").length;
    const grouped = digits.includes(",");
    const render = value => {
      const fixed = value.toFixed(decimals);
      return prefix + (grouped ? Number(fixed).toLocaleString("en-US", {
        minimumFractionDigits: decimals, maximumFractionDigits: decimals,
      }) : fixed) + suffix;
    };
    const started = performance.now(), span = 820;
    const frame = now => {
      if (still()) { el.textContent = text; return; }
      const k = Math.min(1, (now - started) / span);
      el.textContent = render(target * (1 - Math.pow(1 - k, 3)));
      if (k < 1) requestAnimationFrame(frame);
      else el.textContent = text;                    // land on exactly what was rendered
    };
    requestAnimationFrame(frame);
  }

  /* ---------- meters fill from zero ---------- */
  function fillMeters(root) {
    for (const bar of root.querySelectorAll(".bar i, .meter i")) {
      if (bar.dataset.pnFilled) continue;
      bar.dataset.pnFilled = "1";
      const width = bar.style.width;
      if (!width || still()) continue;
      bar.style.width = "0";
      requestAnimationFrame(() => requestAnimationFrame(() => { bar.style.width = width; }));
    }
  }

  /* ---------- the view's opening rule ----------
     Its travelling highlight is one composited animation, but a composited
     animation still asks the display for a frame sixty times a second for as
     long as it runs, so it is held still whenever it is scrolled out of the
     workspace. The rest of its policy — idle, the pause control and reduced
     motion — is CSS, beside the animation in console.css. */
  let leadObserver = null;
  function watchLead(root) {
    if (!("IntersectionObserver" in window)) return;
    leadObserver?.disconnect();
    leadObserver = new IntersectionObserver(entries => {
      for (const entry of entries) entry.target.classList.toggle("is-outside", !entry.isIntersecting);
    });
    for (const lead of root.querySelectorAll(".viewLead")) leadObserver.observe(lead);
  }

  /* Run once per rendered view, and only for what is actually on screen. */
  let observer = null;
  function run(root) {
    if (!root) return;
    watchLead(root);
    const values = root.querySelectorAll(".overviewMetrics b, .kpi b, .viewFacts dd, .metric strong");
    if (still()) {
      root.querySelectorAll(LABELS).forEach(el => { el.dataset.pnScrambled = "1"; });
      values.forEach(el => { el.dataset.pnCounted = "1"; });
      fillMeters(root);
      return;
    }
    if (!("IntersectionObserver" in window)) {
      root.querySelectorAll(LABELS).forEach(scramble);
      values.forEach(countUp);
      fillMeters(root);
      return;
    }
    observer?.disconnect();
    observer = new IntersectionObserver(entries => {
      for (const entry of entries) {
        if (!entry.isIntersecting) continue;
        if (entry.target.matches(LABELS)) scramble(entry.target);
        else countUp(entry.target);
        observer.unobserve(entry.target);
      }
    }, { threshold: .5 });
    root.querySelectorAll(LABELS).forEach(el => observer.observe(el));
    values.forEach(el => observer.observe(el));
    fillMeters(root);
  }

  window.consoleMotion = run;
  reduced.addEventListener("change", () => run(document.querySelector("#view")));
})();
