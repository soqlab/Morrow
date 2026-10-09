(() => {
  "use strict";
  const toggle = document.getElementById("menuToggle");
  const menu = document.getElementById("siteMenu");
  function closeMenu(restoreFocus = false) {
    menu.hidden = true;
    toggle.setAttribute("aria-expanded", "false");
    toggle.setAttribute("aria-label", "Open navigation");
    if (restoreFocus) toggle.focus();
  }
  toggle.addEventListener("click", () => {
    menu.hidden = !menu.hidden;
    toggle.setAttribute("aria-expanded", String(!menu.hidden));
    toggle.setAttribute("aria-label", menu.hidden ? "Open navigation" : "Close navigation");
  });
  menu.addEventListener("click", event => { if (event.target.closest("a")) closeMenu(); });
  document.addEventListener("keydown", event => { if (event.key === "Escape" && !menu.hidden) closeMenu(true); });
  document.addEventListener("click", event => {
    if (!menu.hidden && !menu.contains(event.target) && !toggle.contains(event.target)) closeMenu();
  });
  document.addEventListener("focusin", event => {
    if (!menu.hidden && !menu.contains(event.target) && !toggle.contains(event.target)) closeMenu();
  });
  let headerScrolled = null;
  function syncHeader() {
    const scrolled = window.scrollY > 40;
    if (scrolled !== headerScrolled) { headerScrolled = scrolled; document.body.classList.toggle("header-scrolled", scrolled); }
  }
  window.addEventListener("scroll", syncHeader, { passive: true });
  syncHeader();

  const tabs = [...document.querySelectorAll("[data-chapter]")];
  const fabricButtons = [...document.querySelectorAll("[data-fabric-mode]")];
  const fabricCopy = [
    ["Discover the dependencies.", "A connected view. A controlled boundary."],
    ["Protect the connections.", "A migration path around your applications."],
    ["Carry the evidence forward.", "Scope, provenance, and signatures together."],
  ];
  document.querySelector(".fabric-modes").hidden = false;
  document.getElementById("platformTabs").setAttribute("role", "tablist");
  function selectChapter(tab, focus = false) {
    const index = tabs.indexOf(tab);
    fabricButtons.forEach(button => button.setAttribute("aria-pressed", String(button.dataset.fabricMode === tab.dataset.chapter)));
    document.getElementById("fabricIndex").textContent = String(index + 1).padStart(2, "0");
    document.getElementById("fabricTitle").textContent = fabricCopy[index][0];
    document.getElementById("fabricDescription").textContent = fabricCopy[index][1];
    document.querySelector(".fabric-stage").dataset.mode = tab.dataset.chapter;
    window.airlockScene?.setMode(index);
    tabs.forEach(item => {
      const selected = item === tab;
      const panel = document.getElementById(item.getAttribute("aria-controls"));
      item.setAttribute("role", "tab");
      item.setAttribute("aria-selected", String(selected));
      item.tabIndex = selected ? 0 : -1;
      panel.setAttribute("role", "tabpanel");
      panel.tabIndex = 0;
      panel.hidden = !selected;
    });
    if (focus) tab.focus();
  }
  tabs.forEach((tab, index) => {
    tab.addEventListener("click", () => selectChapter(tab));
    tab.addEventListener("keydown", event => {
      let next;
      if (event.key === "ArrowRight") next = (index + 1) % tabs.length;
      if (event.key === "ArrowLeft") next = (index + tabs.length - 1) % tabs.length;
      if (event.key === "Home") next = 0;
      if (event.key === "End") next = tabs.length - 1;
      if (next === undefined) return;
      event.preventDefault();
      selectChapter(tabs[next], true);
    });
  });
  fabricButtons.forEach(button => button.addEventListener("click", () => {
    selectChapter(tabs.find(tab => tab.dataset.chapter === button.dataset.fabricMode));
  }));
  selectChapter(tabs[0]);


  /* Ticker and statement marquee. The standards this page argues about, and the
     three words the argument comes down to. Both are decoration, so they are
     built here rather than shipped as markup a reader has to download. */
  const tickerTrack = document.getElementById("ticker");
  if (tickerTrack) {
    const items = [
      "ML-KEM-768 <b>FIPS 203</b>", "ML-DSA-65 <b>FIPS 204</b>", "SLH-DSA <b>FIPS 205</b>",
      "X25519MLKEM768 <b>hybrid TLS</b>", "LMS <b>SP 800-208</b>", "HQC <b>backup KEM</b>",
      "RSA-2048 <b>deprecated 2030</b>", "ECDSA P-256 <b>disallowed 2035</b>",
      "CNSA 2.0 <b>2033</b>", "Harvest now, decrypt later",
    ].map(entry => "<span>" + entry + "</span>").join("");
    tickerTrack.innerHTML = items + items;
  }

  /* Countdown to 1 January 2030, after which NIST IR 8547 deprecates 112-bit
     public keys such as RSA-2048 (all RSA and elliptic-curve keys are
     disallowed after 2035). This is arithmetic on a published date, not a modelled figure —
     the only number on this page that moves on its own. */
  const countdown = document.getElementById("cd");
  if (countdown) {
    const DEADLINE = Date.UTC(2030, 0, 1);
    const pad = value => (value < 10 ? "0" : "") + value;
    /* The markup is built once; each second only the text that changed is
       written, and not at all while the countdown is off screen (rewriting the
       whole element every second laid out the page every second). */
    countdown.innerHTML = '0<em>y</em>0<em>d</em>00:00:<span class="sec">00</span>';
    const [yearsText, , daysText, , clockText, secEl] = countdown.childNodes;
    const secText = secEl.firstChild;
    const put = (node, value) => { if (node.nodeValue !== value) node.nodeValue = value; };
    let onScreen = true;
    const tick = () => {
      if (!onScreen) return;
      const remaining = Math.max(0, DEADLINE - Date.now());
      const seconds = Math.floor(remaining / 1000);
      const days = Math.floor(seconds / 86400);
      const years = Math.floor(days / 365);
      put(yearsText, String(years));
      put(daysText, String(days - years * 365));
      put(clockText, pad(Math.floor(seconds % 86400 / 3600)) + ":" + pad(Math.floor(seconds % 3600 / 60)) + ":");
      put(secText, pad(seconds % 60));
    };
    tick();
    setInterval(tick, 1000);
    if ("IntersectionObserver" in window) {
      new IntersectionObserver(entries => {
        onScreen = entries.some(entry => entry.isIntersecting);
        tick();
      }).observe(countdown);
    }
  }

  const reducedMotion = matchMedia("(prefers-reduced-motion: reduce)");
  const motionToggle = document.getElementById("motionToggle");
  const motionLabel = document.getElementById("motionLabel");
  let userPaused = false, heroVisible = true;
  try { userPaused = localStorage.getItem("airlock-motion-paused") === "1"; } catch { /* Preference storage is optional. */ }
  function syncMotion() {
    const paused = userPaused || reducedMotion.matches || document.hidden;
    document.body.dataset.motion = paused ? "paused" : "playing";
    motionToggle.hidden = false;
    motionToggle.disabled = reducedMotion.matches;
    motionToggle.setAttribute("aria-pressed", String(userPaused || reducedMotion.matches));
    motionLabel.textContent = reducedMotion.matches ? "Reduced motion" : userPaused ? "Play motion" : "Pause motion";
    window.airlockScene?.setRunning(!paused && heroVisible);
    // The page sheet is fixed to the viewport, but the hero paints its own
    // opaque ground over it. Only ever run one of the two.
    window.airlockPageFabric?.setRunning(!paused && !heroVisible);
  }
  motionToggle.addEventListener("click", () => {
    userPaused = !userPaused;
    try { localStorage.setItem("airlock-motion-paused", userPaused ? "1" : "0"); } catch { /* Preference storage is optional. */ }
    syncMotion();
  });
  reducedMotion.addEventListener("change", syncMotion);
  document.addEventListener("airlock:scene-ready", syncMotion);
  /* The sweeping rules, the marquee and the scroll cue never end, so on a page
     nobody has touched for a while they are held still: otherwise they alone
     keep the compositor drawing at display rate for no reader. The first sign
     of one starts them again on the frame they stopped at. */
  let idleTimer = 0;
  const active = () => {
    delete document.body.dataset.idle;
    clearTimeout(idleTimer);
    idleTimer = setTimeout(() => { document.body.dataset.idle = "1"; }, 20000);
  };
  for (const type of ["pointermove", "pointerdown", "wheel", "keydown", "scroll", "focusin"]) {
    addEventListener(type, active, { passive: true, capture: true });
  }
  document.addEventListener("visibilitychange", () => { if (!document.hidden) active(); });
  active();
  if ("IntersectionObserver" in window) {
    const motionObserver = new IntersectionObserver(entries => {
      entries.forEach(entry => {
        entry.target.classList.toggle("is-outside", !entry.isIntersecting);
        if (entry.target.classList.contains("hero")) heroVisible = entry.isIntersecting;
      });
      syncMotion();
    });
    motionObserver.observe(document.querySelector(".hero"));
    motionObserver.observe(document.querySelector(".platform-stage"));
    motionObserver.observe(document.querySelector(".boundary"));
    // The ticker, the marquee and each section's sweeping rule rest off screen
    // too: every running CSS animation is restyled on each frame the page draws,
    // and together they were enough to saturate a slower machine's main thread.
    document.querySelectorAll(".ticker, .section-topline").forEach(element => motionObserver.observe(element));
    const marquee = document.querySelector(".st-track")?.parentElement;
    if (marquee) motionObserver.observe(marquee);
    const revealObserver = new IntersectionObserver(entries => {
      entries.forEach(entry => {
        if (!entry.isIntersecting) return;
        entry.target.classList.add("revealed");
        revealObserver.unobserve(entry.target);
      });
    }, { threshold: .08 });
    document.querySelectorAll("[data-reveal]").forEach(element => revealObserver.observe(element));
    document.body.classList.add("reveal-ready");
  }
  syncMotion();

  // Only public API/database health is polled. Decorative scenes never consume tenant data.
  const service = document.getElementById("serviceStatus");
  const serviceLabel = document.getElementById("serviceLabel");
  const serviceChecked = document.getElementById("serviceChecked");
  let serviceVisible = false, pageActive = true, timer = 0, pending = null, lastCheck = 0;
  async function checkStatus() {
    clearTimeout(timer);
    if (pending || document.hidden || !serviceVisible || !pageActive) return;
    const remaining = 60000 - (Date.now() - lastCheck);
    if (remaining > 0) { timer = setTimeout(checkStatus, remaining); return; }
    const controller = new AbortController();
    let completed = false;
    pending = controller;
    const timeout = setTimeout(() => controller.abort(), 8000);
    try {
      const response = await fetch("/status", { cache: "no-store", credentials: "omit", signal: controller.signal });
      if (!response.ok) throw new Error("Status unavailable");
      const data = await response.json();
      const current = Date.parse(data.generated_at);
      const age = Date.now() - current;
      if (!Number.isFinite(current) || age < -300000 || age > 120000 ||
          !["operational", "degraded"].includes(data.status) ||
          !data.checks?.api || !data.checks?.database) throw new Error("Invalid or stale status");
      const healthy = data.status === "operational" &&
        data.checks.api.status === "ok" && data.checks.database.status === "ok";
      service.dataset.state = healthy ? "operational" : "degraded";
      serviceLabel.textContent = healthy ? "API & database operational" : "API or database degraded";
      serviceChecked.textContent = "Checked " + new Date(current).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) + " / refreshes every 60s";
      completed = true;
    } catch {
      if (controller.signal.reason === "inactive") return;
      service.dataset.state = "unavailable";
      serviceLabel.textContent = "API & database status unavailable";
      serviceChecked.textContent = "No current health confirmation. Retrying while visible.";
      completed = true;
    } finally {
      clearTimeout(timeout);
      pending = null;
      if (completed) lastCheck = Date.now();
      if (serviceVisible && !document.hidden && pageActive) timer = setTimeout(checkStatus, completed ? 60000 : 0);
    }
  }
  function syncStatus() {
    clearTimeout(timer);
    if (document.hidden || !serviceVisible || !pageActive) {
      pending?.abort("inactive");
      return;
    }
    if (lastCheck && Date.now() - lastCheck >= 60000) {
      service.dataset.state = "pending";
      serviceLabel.textContent = "Checking API & database status";
    }
    checkStatus();
  }
  if ("IntersectionObserver" in window) {
    new IntersectionObserver(entries => {
      serviceVisible = entries[0].isIntersecting;
      syncStatus();
    }).observe(service);
  } else {
    serviceVisible = true;
    syncStatus();
  }
  document.addEventListener("visibilitychange", () => { syncMotion(); syncStatus(); });
  window.addEventListener("pagehide", () => {
    pageActive = false;
    clearTimeout(timer);
    pending?.abort("inactive");
    window.airlockScene?.setRunning(false);
  });
  window.addEventListener("pageshow", () => { pageActive = true; syncMotion(); syncStatus(); });
})();
