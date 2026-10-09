(() => {
  "use strict";
  /* ==========================================================================
     Motion policy for the generative fabric.
     fabric.js only knows how to draw; this decides when it is allowed to.
     A scene runs only when every one of these holds:
       - the reader has not asked for reduced motion,
       - the reader has not paused it (preference shared across every surface),
       - the tab is visible and the page is not in the back/forward cache,
       - the scene itself is on screen.

     Any element with [data-motion-toggle] becomes a play/pause control; a
     [data-motion-label] inside it receives the current wording.
     ========================================================================== */

  const STORAGE_KEY = "airlock-motion-paused";
  const reducedMotion = matchMedia("(prefers-reduced-motion: reduce)");
  const toggles = [...document.querySelectorAll("[data-motion-toggle]")];
  const visible = new WeakMap();
  let userPaused = false, pageActive = true;

  try { userPaused = localStorage.getItem(STORAGE_KEY) === "1"; } catch { /* Preference storage is optional. */ }

  function scenes() { return window.airlockFabric?.scenes || []; }

  function sync() {
    const blocked = userPaused || reducedMotion.matches || document.hidden || !pageActive;
    document.body.dataset.motion = blocked ? "paused" : "playing";
    for (const scene of scenes()) {
      const host = scene.canvas.parentElement;
      scene.setRunning(!blocked && visible.get(host) !== false);
    }
    for (const toggle of toggles) {
      toggle.hidden = false;
      toggle.disabled = reducedMotion.matches;
      toggle.setAttribute("aria-pressed", String(userPaused || reducedMotion.matches));
      const label = toggle.querySelector("[data-motion-label]") || toggle;
      label.textContent = reducedMotion.matches ? "Reduced motion" : userPaused ? "Play motion" : "Pause motion";
    }
  }

  for (const toggle of toggles) {
    toggle.addEventListener("click", () => {
      userPaused = !userPaused;
      try { localStorage.setItem(STORAGE_KEY, userPaused ? "1" : "0"); } catch { /* Preference storage is optional. */ }
      sync();
    });
  }

  if ("IntersectionObserver" in window) {
    const observer = new IntersectionObserver(entries => {
      for (const entry of entries) visible.set(entry.target, entry.isIntersecting);
      sync();
    });
    for (const scene of scenes()) observer.observe(scene.canvas.parentElement);
  }

  /* ---------- idle ----------
     A decorative animation that never ends is composited on every display frame
     for as long as the tab is open, whether or not anyone is there to see it.
     After a while with nothing touched the page marks itself idle and the CSS
     holds that decoration still; the first sign of a reader starts it again on
     the frame it stopped at. Only decoration is gated this way — spinners and
     skeletons keep running, because they say something is still happening. */
  const IDLE_AFTER = 20000;
  let idleTimer = 0;
  function active() {
    delete document.body.dataset.idle;
    clearTimeout(idleTimer);
    idleTimer = setTimeout(() => { document.body.dataset.idle = "1"; }, IDLE_AFTER);
  }
  for (const type of ["pointermove", "pointerdown", "wheel", "keydown", "scroll", "focusin"]) {
    addEventListener(type, active, { passive: true, capture: true });
  }

  reducedMotion.addEventListener("change", sync);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) active(); sync(); });
  document.addEventListener("airlock:scene-ready", sync);
  window.addEventListener("pagehide", () => { pageActive = false; sync(); });
  window.addEventListener("pageshow", () => { pageActive = true; sync(); });
  sync();

  active();

  window.airlockMotion = { sync, get paused() { return userPaused || reducedMotion.matches; } };
})();
