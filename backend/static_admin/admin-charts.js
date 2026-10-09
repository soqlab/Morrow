(() => {
  "use strict";
  /* ==========================================================================
     Operator console charts: crisp inline SVG, drawn once per data change.

       timeSeries(host, cfg)  line, area, columns or stacked columns over time,
                              with a snapping crosshair, one tooltip for every
                              series, keyboard stepping and a table view
       sparkline(values)      a 12-ish point trend for stat tiles (SVG string)
       bars(host, cfg)        horizontal bars with the value at each tip

     Nothing animates. A chart redraws only when its data changes or its box
     changes width, so a dashboard left open all day costs nothing at rest.
     Labels and values come from API responses, so every string reaches the DOM
     through textContent or esc(), never raw.
     ========================================================================== */

  const NS = "http://www.w3.org/2000/svg";
  const nf = new Intl.NumberFormat();
  const esc = value => String(value ?? "").replace(/[&<>"']/g, ch => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[ch]));
  const num = value => (value === null || value === undefined || value === "" || !Number.isFinite(Number(value)) ? null : Number(value));

  function compact(value) {
    const n = num(value);
    if (n === null) return "—";
    const a = Math.abs(n);
    if (a >= 1e9) return `${(n / 1e9).toFixed(a >= 1e10 ? 0 : 1)}B`;
    if (a >= 1e6) return `${(n / 1e6).toFixed(a >= 1e7 ? 0 : 1)}M`;
    if (a >= 1e4) return `${(n / 1e3).toFixed(a >= 1e5 ? 0 : 1)}K`;
    return Number.isInteger(n) ? nf.format(n) : nf.format(Math.round(n * 10) / 10);
  }
  const formats = {
    count: v => (num(v) === null ? "—" : nf.format(Math.round(num(v) * 100) / 100)),
    compact,
    ms: v => (num(v) === null ? "—" : `${nf.format(Math.round(num(v)))} ms`),
    pct: v => (num(v) === null ? "—" : `${(Math.round(num(v) * 100) / 100).toFixed(num(v) < 10 ? 2 : 1)}%`)
  };

  function parseTime(t) {
    if (t === null || t === undefined || t === "") return null;
    if (typeof t === "number") return new Date(t < 1e12 ? t * 1000 : t);
    const raw = String(t);
    if (/^\d+(\.\d+)?$/.test(raw)) return parseTime(Number(raw));
    const date = new Date(raw);
    return Number.isNaN(date.getTime()) ? null : date;
  }
  function timeLabel(t, bucket, long) {
    const d = parseTime(t);
    if (!d) return String(t ?? "");
    if (bucket === "hour") {
      const hm = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      return long ? `${d.toLocaleDateString([], { month: "short", day: "numeric" })} ${hm}` : hm;
    }
    return d.toLocaleDateString([], long ? { weekday: "short", month: "short", day: "numeric" } : { month: "short", day: "numeric" });
  }

  // Clean axis ticks: 0 then round steps (1, 2, 2.5, 5 × 10^n) up to the data max.
  function niceTicks(max, count = 4) {
    if (!(max > 0)) return [0, 1];
    const raw = max / count;
    const mag = Math.pow(10, Math.floor(Math.log10(raw)));
    const step = [1, 2, 2.5, 5, 10].map(m => m * mag).find(s => s >= raw) || 10 * mag;
    const top = Math.ceil(max / step) * step;
    const ticks = [];
    for (let v = 0; v <= top + step / 1e6; v += step) ticks.push(Math.round(v * 1e6) / 1e6);
    return ticks;
  }

  function el(name, attrs = {}, parent) {
    const node = document.createElementNS(NS, name);
    for (const [k, v] of Object.entries(attrs)) if (v !== undefined && v !== null) node.setAttribute(k, String(v));
    if (parent) parent.appendChild(node);
    return node;
  }
  // Column with a 4px rounded data end and a square foot on the baseline.
  function columnPath(x, y, w, h, r = 4) {
    const rr = Math.max(0, Math.min(r, w / 2, h));
    return `M${x},${y + h}V${y + rr}Q${x},${y} ${x + rr},${y}H${x + w - rr}Q${x + w},${y} ${x + w},${y + rr}V${y + h}Z`;
  }

  const mounted = new WeakMap();

  function timeSeries(host, cfg) {
    if (!host) return;
    const state = mounted.get(host) || {};
    state.cfg = cfg;
    if (!state.ro && "ResizeObserver" in window) {
      state.width = 0;
      state.ro = new ResizeObserver(() => {
        const w = Math.round(host.clientWidth);
        if (Math.abs(w - state.width) < 4 || !w) return;
        if (!state.queued) { state.queued = true; requestAnimationFrame(() => { state.queued = false; draw(host, state); }); }
      });
      state.ro.observe(host);
    }
    mounted.set(host, state);
    draw(host, state);
  }

  function draw(host, state) {
    const cfg = state.cfg || {};
    const data = Array.isArray(cfg.data) ? cfg.data : [];
    const series = (cfg.series || []).filter(s => s && s.key);
    const kind = cfg.kind || "line";
    const format = typeof cfg.format === "function" ? cfg.format : formats[cfg.format || "count"];
    const tickFormat = cfg.format === "ms" ? v => compact(v) : cfg.format === "pct" ? v => `${compact(v)}%` : compact;
    const width = Math.max(240, Math.round(host.clientWidth) || 560);
    state.width = width;
    const height = cfg.height || 210;
    host.classList.add("chHost");
    host.textContent = "";

    if (series.length > 1) {
      const legend = document.createElement("ul");
      legend.className = "chLegend";
      series.forEach(s => {
        const li = document.createElement("li");
        const key = document.createElement("i");
        key.className = kind === "line" ? "chKeyLine" : "chKeyBox";
        key.style.background = `var(${s.color})`;
        li.append(key, document.createTextNode(s.label));
        legend.appendChild(li);
      });
      host.appendChild(legend);
    }
    if (cfg.caption) {
      const cap = document.createElement("p");
      cap.className = "chCaption";
      cap.textContent = cfg.caption;
      host.appendChild(cap);
    }
    if (!data.length || !series.length) {
      const note = document.createElement("div");
      note.className = "chEmpty";
      note.textContent = cfg.emptyText || "No data points in this range.";
      host.appendChild(note);
      return;
    }

    if (data.every(row => series.every(sr => num(row[sr.key]) === null))) {
      const note = document.createElement("div");
      note.className = "chEmpty";
      note.textContent = "No retained data for this range.";
      host.appendChild(note);
      return;
    }
    const stacked = kind === "stacked";
    const columns = kind === "columns" || stacked;
    const values = data.map(row => series.map(s => num(row[s.key])));
    const totals = values.map(vs => (vs.every(v => v === null) ? null : vs.reduce((a, v) => a + (v || 0), 0)));
    const max = stacked ? Math.max(0, ...totals.map(v => v || 0)) : Math.max(0, ...values.flat().map(v => v || 0));
    const ticks = niceTicks(max);
    const top = ticks[ticks.length - 1] || 1;
    const labelChars = Math.max(...ticks.map(t => tickFormat(t).length));
    const m = { l: Math.max(28, labelChars * 6.6 + 12), r: 10, t: 8, b: 24 };
    const pw = width - m.l - m.r, ph = height - m.t - m.b;
    const n = data.length;
    const band = pw / n;
    const xAt = i => (columns || n === 1 ? m.l + band * (i + 0.5) : m.l + (pw * i) / (n - 1));
    const yAt = v => m.t + ph - (Math.max(0, v) / top) * ph;

    const wrap = document.createElement("div");
    wrap.className = "chPlot";
    host.appendChild(wrap);
    const svg = el("svg", { width, height, viewBox: `0 0 ${width} ${height}`, class: "chSvg", role: "img", tabindex: 0, "aria-label": `${cfg.label || "Chart"}: ${n} points. Use left and right arrows to read values.` }, wrap);

    // Grid and y ticks.
    const grid = el("g", { class: "chGrid" }, svg);
    ticks.forEach(t => {
      const y = Math.round(yAt(t)) + 0.5;
      el("line", { x1: m.l, x2: width - m.r, y1: y, y2: y }, grid);
      const label = el("text", { x: m.l - 8, y: y + 3.5, "text-anchor": "end", class: "chTick" }, grid);
      label.textContent = tickFormat(t);
    });
    // X ticks: at most ~6 labels, always the last one.
    const maxLabels = Math.max(2, Math.min(6, Math.floor(pw / 78)));
    const step = Math.max(1, Math.ceil(n / maxLabels));
    const shown = new Set();
    for (let i = n - 1; i >= 0; i -= step) shown.add(i);
    shown.forEach(i => {
      const x = xAt(i);
      const label = el("text", { x, y: height - 6, "text-anchor": i === n - 1 && !columns && n > 1 ? "end" : i === 0 && !columns ? "start" : "middle", class: "chTick" }, grid);
      label.textContent = timeLabel(data[i].t, cfg.bucket);
    });

    const hoverBand = el("rect", { class: "chBand", y: m.t, height: ph, width: Math.max(2, band), x: -999 }, svg);
    const marks = el("g", {}, svg);
    if (columns) {
      const barW = Math.max(2, Math.min(24, band * 0.64));
      values.forEach((vs, i) => {
        const x = xAt(i) - barW / 2;
        if (stacked) {
          let base = 0;
          const present = vs.map((v, k) => [v || 0, k]).filter(([v]) => v > 0);
          present.forEach(([v, k], idx) => {
            const y0 = yAt(base), y1 = yAt(base + v);
            base += v;
            const isTop = idx === present.length - 1;
            const gap = idx > 0 ? 2 : 0; // surface gap between stacked segments
            const h = Math.max(0, y0 - y1 - gap);
            if (h <= 0) return;
            el("path", { d: isTop ? columnPath(x, y1, barW, h) : `M${x},${y1}h${barW}v${h}h${-barW}Z`, style: `fill:var(${series[k].color})` }, marks);
          });
        } else {
          const v = vs[0] || 0;
          if (v <= 0) return;
          const y = yAt(v);
          el("path", { d: columnPath(x, y, barW, m.t + ph - y), style: `fill:var(${series[0].color})` }, marks);
        }
      });
    } else {
      series.forEach((s, k) => {
        const pts = values.map((vs, i) => (vs[k] === null ? null : [xAt(i), yAt(vs[k])]));
        let d = "", open = false;
        pts.forEach(p => { if (!p) { open = false; return; } d += `${open ? "L" : "M"}${p[0].toFixed(1)},${p[1].toFixed(1)}`; open = true; });
        if (!d) return;
        if (kind === "area") {
          const valid = pts.filter(Boolean);
          const area = `${d}L${valid[valid.length - 1][0].toFixed(1)},${m.t + ph}L${valid[0][0].toFixed(1)},${m.t + ph}Z`;
          el("path", { d: area, class: "chArea", style: `fill:var(${s.color})` }, marks);
        }
        el("path", { d, class: "chLine", style: `stroke:var(${s.color})` }, marks);
        if (n === 1 || pts.filter(Boolean).length === 1) {
          const p = pts.find(Boolean);
          el("circle", { cx: p[0], cy: p[1], r: 4, class: "chDot", style: `fill:var(${s.color})` }, marks);
        }
      });
    }
    // Baseline.
    el("line", { x1: m.l, x2: width - m.r, y1: m.t + ph + 0.5, y2: m.t + ph + 0.5, class: "chBase" }, svg);

    const cross = el("line", { class: "chCross", y1: m.t, y2: m.t + ph, x1: -999, x2: -999 }, svg);
    const dots = columns ? [] : series.map(s => el("circle", { r: 4, cx: -999, cy: -999, class: "chDot ring", style: `fill:var(${s.color})` }, svg));
    const hit = el("rect", { x: m.l, y: m.t, width: pw, height: ph, class: "chHit" }, svg);

    const tip = document.createElement("div");
    tip.className = "chTip";
    tip.hidden = true;
    wrap.appendChild(tip);
    let current = -1;
    function show(i) {
      if (i < 0 || i >= n) { hide(); return; }
      current = i;
      const x = xAt(i);
      if (columns) { hoverBand.setAttribute("x", x - band / 2); hoverBand.setAttribute("width", Math.max(2, band)); }
      else { cross.setAttribute("x1", x); cross.setAttribute("x2", x); }
      dots.forEach((dot, k) => {
        const v = values[i][k];
        dot.setAttribute("cx", v === null ? -999 : x);
        dot.setAttribute("cy", v === null ? -999 : yAt(v));
      });
      tip.textContent = "";
      const head = document.createElement("div");
      head.className = "chTipHead";
      head.textContent = timeLabel(data[i].t, cfg.bucket, true);
      tip.appendChild(head);
      const rows = series.map((s, k) => [s, values[i][k]]);
      (stacked ? rows.slice().reverse() : rows).forEach(([s, v]) => {
        const row = document.createElement("div");
        row.className = "chTipRow";
        const key = document.createElement("i");
        key.style.background = `var(${s.color})`;
        const value = document.createElement("b");
        value.textContent = format(v);
        const label = document.createElement("span");
        label.textContent = s.label;
        row.append(key, value, label);
        tip.appendChild(row);
      });
      if (stacked && series.length > 1) {
        const row = document.createElement("div");
        row.className = "chTipRow total";
        const value = document.createElement("b");
        value.textContent = format(totals[i]);
        const label = document.createElement("span");
        label.textContent = cfg.totalLabel || "Total";
        row.append(document.createElement("i"), value, label);
        tip.appendChild(row);
      }
      tip.hidden = false;
      const tw = tip.offsetWidth;
      const left = x + 14 + tw > width ? x - tw - 14 : x + 14;
      tip.style.left = `${Math.max(0, left)}px`;
      tip.style.top = `${m.t}px`;
    }
    function hide() {
      current = -1;
      tip.hidden = true;
      cross.setAttribute("x1", -999); cross.setAttribute("x2", -999);
      hoverBand.setAttribute("x", -999);
      dots.forEach(dot => { dot.setAttribute("cx", -999); });
    }
    function indexAt(clientX) {
      const r = svg.getBoundingClientRect();
      const x = (clientX - r.left) * (width / r.width);
      if (columns || n === 1) return Math.max(0, Math.min(n - 1, Math.floor((x - m.l) / band)));
      return Math.max(0, Math.min(n - 1, Math.round(((x - m.l) / pw) * (n - 1))));
    }
    hit.addEventListener("pointermove", ev => show(indexAt(ev.clientX)));
    hit.addEventListener("pointerleave", hide);
    svg.addEventListener("keydown", ev => {
      if (ev.key === "ArrowRight" || ev.key === "ArrowLeft") {
        ev.preventDefault();
        show(current < 0 ? n - 1 : Math.max(0, Math.min(n - 1, current + (ev.key === "ArrowRight" ? 1 : -1))));
      } else if (ev.key === "Escape") hide();
    });
    svg.addEventListener("blur", hide);

    // Table view: every value reachable without hovering.
    const details = document.createElement("details");
    details.className = "chTable";
    details.innerHTML = `<summary>View as table</summary><div class="tableWrap"><table class="dataTable"><thead><tr><th>${cfg.bucket === "hour" ? "Hour" : "Day"}</th>${series.map(s => `<th class="num">${esc(s.label)}</th>`).join("")}</tr></thead><tbody>${data.map((row, i) => `<tr><td class="mono">${esc(timeLabel(row.t, cfg.bucket, true))}</td>${series.map((s, k) => `<td class="num">${esc(format(values[i][k]))}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
    host.appendChild(details);
  }

  // A small trend for a stat tile. Values in order, oldest first.
  function sparkline(values, { width = 104, height = 30, color = "--c-iris" } = {}) {
    const pts = (values || []).map(num);
    const valid = pts.filter(v => v !== null);
    if (valid.length < 2) return "";
    const max = Math.max(...valid), min = Math.min(0, ...valid), span = max - min || 1;
    const n = pts.length;
    const xy = pts.map((v, i) => (v === null ? null : [2 + ((width - 6) * i) / (n - 1), height - 3 - ((v - min) / span) * (height - 6)]));
    let d = "", open = false;
    xy.forEach(p => { if (!p) { open = false; return; } d += `${open ? "L" : "M"}${p[0].toFixed(1)},${p[1].toFixed(1)}`; open = true; });
    const last = [...xy].reverse().find(Boolean);
    return `<svg class="spark" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" aria-hidden="true" focusable="false"><path d="${d}" style="stroke:var(--c-muted)"/><circle cx="${last[0].toFixed(1)}" cy="${last[1].toFixed(1)}" r="2.5" style="fill:var(${esc(color)})"/></svg>`;
  }

  // Horizontal bars, value at the tip. items: [{ label, value, max?, detail? }]
  function bars(host, { items = [], max, format = compact, color = "--c-iris", emptyText = "Nothing to show yet." } = {}) {
    if (!host) return;
    const rows = items.filter(i => num(i.value) !== null);
    if (!rows.length) { host.innerHTML = `<div class="chEmpty">${esc(emptyText)}</div>`; return; }
    const top = max || Math.max(1, ...rows.map(i => num(i.value)));
    host.innerHTML = `<ul class="chBars">${rows.map(i => {
      const pct = Math.max(0, Math.min(100, (num(i.value) / top) * 100));
      return `<li title="${esc(`${i.label}: ${format(i.value)}${i.detail ? ` · ${i.detail}` : ""}`)}"><span class="chBarLabel">${esc(i.label)}</span><span class="chBarTrack"><i style="width:${pct.toFixed(2)}%;background:var(${esc(color)})"></i></span><b class="chBarValue">${esc(format(i.value))}</b></li>`;
    }).join("")}</ul>`;
  }

  window.AdminCharts = { timeSeries, sparkline, bars, formats, compact, timeLabel, parseTime, niceTicks };
})();
