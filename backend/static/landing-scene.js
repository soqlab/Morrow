(() => {
  "use strict";
  /* The landing mounts two scenes from the shared renderer in fabric.js:
     the hero constellation, and a page-wide field that carries the same points
     through the sections below. landing.js owns when either of them is allowed
     to run — see its motion controller. */
  const art = document.querySelector(".hero-art");
  if (!art || !window.airlockFabric) return;
  window.airlockScene = window.airlockFabric.mount(art, { form: "hero" });
  const page = document.querySelector(".page-fabric");
  window.airlockPageFabric = page && window.airlockFabric.scenes.find(scene => scene.canvas.parentElement === page);
})();
