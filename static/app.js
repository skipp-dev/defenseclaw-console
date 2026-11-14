"use strict";
// DefenseClaw Console – front end. Content always goes in via textContent, never as HTML.

const KEY = (location.pathname.match(/^\/k\/([^/]+)\//) || [])[1] || "";
const INTERVAL_MS = 10000;
const CONFIRMATION_WORD = "ENFORCE";
const COLOR = { allowed: "var(--normal)", would_block: "var(--warning)", blocked: "var(--danger)", unknown: "var(--muted)" };
const VERDICT_TEXT = { allowed: "✓ allowed", would_block: "⚠ would block", blocked: "⛔ blocked", unknown: "? unknown" };
const VERDICTS = ["allowed", "would_block", "blocked", "unknown"];
const KIND_TEXT = {
  tool_invocation: "Tool", llm_prompt: "Prompt", llm_response: "Response", hook_decision: "Decision",
  "scan-finding": "Scan finding", "watcher-block": "Watcher", quarantine: "Quarantine",
  "protected-file-changed": "Protected file", alert: "Alert",
};
const FIELD_TEXT = {
  "gen_ai.tool.call.arguments": "Tool input", "gen_ai.tool.call.result": "Tool result",
  "gen_ai.input.messages": "Prompt", "gen_ai.output.messages": "Model response",
};

const last = new Map();
const ui = { state: null, counts: null, events: [], eventErrors: [], open: new Set(), details: new Map(), confirming: false, table: false };

// ---------- helpers ----------
function el(tag, attrs = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") e.className = v;
    else if (k === "text") e.textContent = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v === true ? "" : v);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    e.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return e;
}
const $ = (id) => document.getElementById(id);
const num = (n) => (n ?? 0).toLocaleString("en-US");
function time(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  return isNaN(d) ? iso : d.toLocaleString("en-GB", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", second: "2-digit" });
}
async function get(path) {
  const r = await fetch(path, { headers: { "X-Console-Key": KEY }, cache: "no-store" });
  if (!r.ok) throw new Error(`${path}: HTTP ${r.status}`);
  return r.json();
}
let noticeTimer;
function notify(text, error = false) {
  const m = $("notice");
  m.textContent = text;
  m.className = "notice" + (error ? " error" : "");
  m.hidden = false;
  clearTimeout(noticeTimer);
  noticeTimer = setTimeout(() => (m.hidden = true), error ? 12000 : 6000);
}
let actionRunning = false;
async function act(action, target, confirmation = "") {
  if (actionRunning) { notify("Please wait – the previous action is still running.", true); return; }
  actionRunning = true;
  document.body.classList.add("busy");
  notify(`Running: ${action} ${target} … (DefenseClaw takes a few seconds)`);
  try {
    // The server only replies once it has loaded the new state.
    const r = await fetch("/api/action", {
      method: "POST", cache: "no-store",
      headers: { "Content-Type": "application/json", "X-Console-Key": KEY },
      body: JSON.stringify({ action, target, confirmation }),
    });
    const j = await r.json();
    notify(`${j.ok ? "Done" : "Not executed"}: ${action} ${target}\n${j.output || ""}`.trim(), !j.ok);
  } catch (e) {
    notify(`Error: ${e.message}`, true);
  } finally {
    actionRunning = false;
    document.body.classList.remove("busy");
    refresh();
  }
}

// ---------- header ----------
function badge(text, kind) {
  return el("span", { class: `badge ${kind || ""}` }, el("span", { class: "dot" }), text);
}
function connector() {
  const c = ui.state?.status?.connectors;
  return Array.isArray(c) ? c.find((x) => x.name === "claudecode") || c[0] : null;
}
function watcherAlertsOnly(config) {
  if (!config) return null;
  return /take_action:\s*false/.test(config) && /auto_block:\s*false/.test(config) && !/take_action:\s*true/.test(config);
}
function drawHeader() {
  const z = ui.state || {};
  const c = connector();
  const p = $("badges");
  p.replaceChildren();
  const running = z.status?.sidecar?.running;
  const service = z.loading ? ["Checking gateway …", ""]
    : running === false ? ["Gateway stopped", "danger"]
    : z.reachable ? ["Gateway running", "good"]
    : ["Gateway unreachable – values are stale", "danger"];
  p.append(badge(service[0], service[1]));
  if (c) {
    p.append(badge(c.mode === "action" ? "Mode: enforce" : "Mode: observe", c.mode === "action" ? "warn" : "good"));
    const fm = c.fail_mode?.effective;
    p.append(badge(fm === "open" ? "Outage: let through" : `Outage: ${fm || "?"}`, fm === "open" ? "good" : "warn"));
  }
  if (z.loading) { drawAsOf(z); return; }
  const local = /scanner_mode:\s*local/.test(z.config || "");
  p.append(badge(local ? "Local rules only" : "Cisco AI Defense active?", local ? "good" : "warn"));
  const w = watcherAlertsOnly(z.config);
  p.append(badge(w ? "Watcher: alert only" : w === false ? "Watcher: takes action" : "Watcher ?", w ? "good" : "warn"));
  drawAsOf(z);
}
function drawAsOf(z) {
  const s = $("as-of");
  const age = z.as_of ? (Date.now() - new Date(z.as_of)) / 1000 : null;
  s.textContent = z.loading ? "loading DefenseClaw data …" : `As of ${time(z.as_of)}${z.errors?.length ? " · " + z.errors.length + " errors" : ""}`;
  s.className = "as-of" + (age !== null && age > 60 ? " stale" : "");
  s.title = (z.errors || []).join("\n");
}

// ---------- tiles and chart ----------
function drawTiles() {
  const z = ui.counts || {};
  const active = $("filter-verdict").value;
  const tile = (name, value, cls, sub) => {
    const body = [el("div", { class: "name" }, cls ? el("span", { class: `swatch ${cls}` }) : null, name),
      el("div", { class: "value", text: num(value) }), el("div", { class: "sub", text: sub })];
    if (!cls) return el("div", { class: "tile" }, ...body);
    return el("button", {
      type: "button", class: "tile clickable" + (active === cls ? " active" : ""), "aria-pressed": String(active === cls),
      title: active === cls ? "show all events again" : "show these decisions in the event list",
      onclick: () => showVerdict(active === cls ? "" : cls),
    }, ...body);
  };
  $("tiles").replaceChildren(...[
    tile("seen", z.seen, null, "checkpoint decisions, last 24 h"),
    tile("✓ allowed", z.allowed, "allowed", "no finding"),
    tile("⚠ would block", z.would_block, "would_block", "finding, let through in observe mode"),
    tile("⛔ blocked", z.blocked, "blocked", "actually blocked"),
    z.unknown ? tile("? unknown", z.unknown, "unknown", "decision without a known value – check the DefenseClaw version") : null,
  ].filter(Boolean));
}
// Clicking a tile filters the event list to exactly these decisions (last 24 h, like the tile).
function showVerdict(verdict) {
  $("filter-verdict").value = verdict;
  if (verdict) $("filter-kind").value = "hook_decision";
  ui.open.clear();
  drawTiles();
  refresh();
  if (verdict) $("events-card").scrollIntoView({ behavior: "smooth", block: "start" });
}
function drawLegend() {
  $("legend").replaceChildren(...VERDICTS.map((k) =>
    el("span", {}, el("span", { class: `swatch ${k}` }), VERDICT_TEXT[k])));
}
function drawChart() {
  const rows = ui.counts?.per_hour || [];
  const target = $("chart");
  const tab = $("chart-table");
  tab.replaceChildren(el("table", {}, el("thead", {}, el("tr", {}, el("th", { text: "Hour (UTC)" }),
    ...["seen", "allowed", "would block", "blocked", "unknown"].map((t) => el("th", { class: "num", text: t })))),
    el("tbody", {}, ...rows.map((h) => el("tr", {}, el("td", { text: h.hour.replace("T", " ") + ":00" }),
      ...["seen", ...VERDICTS].map((k) => el("td", { class: "num", text: num(h[k]) })))))));
  tab.hidden = !ui.table;
  target.hidden = ui.table;
  if (!rows.length) { target.replaceChildren(el("p", { class: "hint", text: "No decisions in the last 24 hours yet." })); return; }
  const W = 1000, H = 190, left = 44, bottom = 22, top = 8;
  const max = Math.max(1, ...rows.map((h) => h.seen));
  const step = (W - left) / rows.length;
  const width = Math.max(2, Math.min(28, step - 2));
  const y = (v) => top + (H - bottom - top) * (1 - v / max);
  const ns = "http://www.w3.org/2000/svg";
  const s = (tag, a) => { const e = document.createElementNS(ns, tag); for (const [k, v] of Object.entries(a)) e.setAttribute(k, v); return e; };
  const svg = s("svg", { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none", role: "img", "aria-label": "Decisions per hour" });
  for (const t of [0, 0.5, 1]) {
    const v = Math.round(max * t);
    svg.append(s("line", { x1: left, x2: W, y1: y(v), y2: y(v), class: "grid" }));
    const txt = s("text", { x: left - 6, y: y(v) + 4, "text-anchor": "end", class: "axis" }); txt.textContent = num(v); svg.append(txt);
  }
  rows.forEach((h, i) => {
    const x = left + i * step + (step - width) / 2;
    let base = 0;
    for (const k of VERDICTS) {
      const v = h[k] || 0;
      if (!v) continue;
      const y1 = y(base + v), y0 = y(base);
      svg.append(s("rect", { x, y: y1, width, height: Math.max(1, y0 - y1 - (base ? 2 : 0)), rx: 2, fill: COLOR[k], class: "bar" }));
      base += v;
    }
    if (i % Math.ceil(rows.length / 12) === 0) {
      const txt = s("text", { x: x + width / 2, y: H - 6, "text-anchor": "middle", class: "axis" });
      txt.textContent = new Date(h.hour + ":00:00Z").toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
      svg.append(txt);
    }
    const hit = s("rect", { x: left + i * step, y: 0, width: step, height: H - bottom, class: "hit" });
    hit.addEventListener("mousemove", (ev) => showTip(ev, h));
    hit.addEventListener("mouseleave", () => ($("tip").hidden = true));
    svg.append(hit);
  });
  target.replaceChildren(svg);
}
function showTip(ev, h) {
  const t = $("tip");
  const local = new Date(h.hour + ":00:00Z").toLocaleString("en-GB", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" });
  t.replaceChildren(el("strong", { text: local }),
    ...[["seen", "seen"], ...VERDICTS.filter((k) => k !== "unknown" || h.unknown).map((k) => [k, VERDICT_TEXT[k]])]
      .map(([k, n]) => el("div", {}, el("span", { text: n }), el("span", { text: num(h[k]) }))));
  t.hidden = false;
  t.style.left = Math.min(ev.clientX + 14, innerWidth - 200) + "px";
  t.style.top = ev.clientY + 14 + "px";
}

// ---------- mode ----------
function drawMode() {
  const c = connector();
  last.set("mode", JSON.stringify([c?.mode, ui.confirming]));
  const target = $("mode");
  if (!c) { target.replaceChildren(el("p", { class: "hint", text: "No data yet." })); return; }
  const enforcing = c.mode === "action";
  const parts = [
    el("div", { class: "mode-row" },
      el("span", { class: "mode-value", text: enforcing ? "enforce" : "observe" }),
      enforcing
        ? el("button", { class: "btn", type: "button", text: "switch back to observe", onclick: () => act("mode", "observe") })
        : el("button", { class: "btn danger", type: "button", text: "switch to enforce …", onclick: () => { ui.confirming = true; drawMode(); } })),
    el("p", { class: "hint", text: enforcing
      ? "Findings are blocked – in every Claude Code session."
      : "Findings are only recorded; calls keep running." }),
  ];
  if (ui.confirming && !enforcing) {
    const input = el("input", { placeholder: `type ${CONFIRMATION_WORD}`, "aria-label": "Confirmation", autocomplete: "off" });
    const go = el("button", { class: "btn danger", type: "button", text: "switch now", disabled: true,
      onclick: () => { ui.confirming = false; act("mode", "action", input.value); } });
    input.addEventListener("input", () => (go.disabled = input.value !== CONFIRMATION_WORD));
    parts.push(el("div", { class: "confirm" },
      el("p", { text: "Takes effect immediately in every running Claude Code session and in scheduled runs. Findings (including false positives) then block the call." }),
      el("div", { class: "form-row" }, input, go,
        el("button", { class: "btn quiet", type: "button", text: "cancel", onclick: () => { ui.confirming = false; drawMode(); } }))));
  }
  target.replaceChildren(...parts);
}

// ---------- sessions ----------
function drawSessions() {
  const j = ui.counts?.per_session || {};
  const rows = Object.entries(j).sort((a, b) => b[1].seen - a[1].seen);
  const sel = $("filter-session");
  const chosen = sel.value;
  sel.replaceChildren(el("option", { value: "", text: "all sessions" }),
    ...rows.map(([sid]) => el("option", { value: sid, text: sid, selected: sid === chosen })));
  $("sessions").replaceChildren(rows.length ? el("table", {},
    el("thead", {}, el("tr", {}, el("th", { text: "Session" }), el("th", { class: "num", text: "seen" }),
      el("th", { class: "num", text: "✓" }), el("th", { class: "num", text: "⚠" }), el("th", { class: "num", text: "⛔" }))),
    el("tbody", {}, ...rows.map(([sid, w]) => el("tr", {}, el("td", { class: "sid", text: sid }),
      el("td", { class: "num", text: num(w.seen) }), el("td", { class: "num", text: num(w.allowed) }),
      el("td", { class: "num", text: num(w.would_block) }), el("td", { class: "num", text: num(w.blocked) })))))
    : el("p", { class: "hint", text: "No sessions in the last 24 hours." }));
}

// ---------- events ----------
function detailRow(id) {
  const d = ui.details.get(id);
  const td = el("td", { colspan: 6 });
  if (!d) td.append(el("span", { class: "muted", text: "loading …" }));
  else if (d.errors) td.append(el("span", { class: "muted", text: d.errors.join(", ") }));
  else {
    for (const row of [d.row, ...(d.related || [])]) {
      const head = `${KIND_TEXT[row.kind] || row.kind} · ${time(row.time)}${row.tool ? " · " + row.tool : ""}`;
      td.append(el("div", { class: "content-title", text: head }));
      for (const [field, text] of Object.entries(row.contents || {})) {
        const n = row.truncated_from?.[field];
        td.append(el("div", { class: "muted", text: (FIELD_TEXT[field] || field) + (n ? ` (truncated, ${num(n)} chars)` : "") }), el("pre", { class: "code", text }));
      }
      if (row.details) td.append(el("pre", { class: "code", text: row.details }));
      const f = row.fields || {};
      const brief = Object.fromEntries(Object.entries(f).filter(([k]) => /guardrail|hook\.event|security|rule|finding|scan\.(verdict|severity)|tool\.(name|status)/.test(k)));
      if (Object.keys(brief).length) td.append(el("pre", { class: "code", text: JSON.stringify(brief, null, 2) }));
    }
  }
  return el("tr", { class: "detail" }, td);
}
async function toggle(id) {
  if (ui.open.has(id)) { ui.open.delete(id); drawEvents(); if (!ui.open.size) refresh(); return; }
  $("events-paused").hidden = false;
  ui.open.add(id);
  drawEvents();
  try { ui.details.set(id, await get(`/api/event/${encodeURIComponent(id)}`)); }
  catch (e) { ui.details.set(id, { errors: [e.message] }); }
  drawEvents();
}
function drawEvents() {
  const rows = [];
  for (const e of ui.events) {
    rows.push(el("tr", { class: "clickable" + (ui.open.has(e.id) ? " open" : ""), onclick: () => toggle(e.id) },
      el("td", { class: "time", text: time(e.time) }),
      el("td", { text: KIND_TEXT[e.kind] || e.kind }),
      el("td", { class: "sid", text: (e.session || "").slice(0, 8) }),
      el("td", { text: e.tool }),
      el("td", {}, e.verdict ? el("span", { class: `verdict ${e.verdict}`, text: VERDICT_TEXT[e.verdict] })
        : el("span", { class: `severity ${e.severity}`, text: e.severity })),
      el("td", { class: "summary", text: e.summary })));
    if (ui.open.has(e.id)) rows.push(detailRow(e.id));
  }
  $("events").replaceChildren(ui.events.length ? el("table", {},
    el("thead", {}, el("tr", {}, ...["Time", "Kind", "Session", "Tool", "Result", "Summary"].map((t) => el("th", { text: t })))),
    el("tbody", {}, rows))
    : el("p", { class: "hint", text: ui.eventErrors.length
      ? "Events cannot be read right now: " + ui.eventErrors.join("; ")
      : "No events for this filter." }));
}

// ---------- alerts ----------
function drawAlerts() {
  const all = Array.isArray(ui.state?.alerts) ? ui.state.alerts : [];
  const level = $("filter-severity").value;
  const search = $("filter-alert").value.toLowerCase();
  const list = all.filter((a) => (!level || a.severity === level) &&
    (!search || `${a.target} ${a.rule} ${a.details}`.toLowerCase().includes(search)));
  const total = ui.state?.status?.activity?.active_alerts;
  $("alert-count").textContent = `– ${num(list.length)} shown` + (total ? `, ${num(total)} active in total (newest 200 loaded)` : "");
  $("alerts").replaceChildren(list.length ? el("table", {},
    el("thead", {}, el("tr", {}, ...["Time", "Severity", "Target", "Rule", "Session", ""].map((t) => el("th", { text: t })))),
    el("tbody", {}, ...list.map((a) => el("tr", {},
      el("td", { class: "time", text: time(a.timestamp) }),
      el("td", {}, el("span", { class: `severity ${a.severity}`, text: a.severity })),
      el("td", { class: "summary", text: a.target }),
      el("td", { text: a.rule || a.details || a.action }),
      el("td", { class: "sid", text: (a.session_id || "").slice(0, 8) }),
      el("td", {}, el("div", { class: "btn-row" },
        el("button", { class: "btn", type: "button", text: "acknowledge", title: "mark as seen", onclick: () => act("alert_ack", a.id) }),
        el("button", { class: "btn", type: "button", text: "dismiss", title: "remove from the active alert list", onclick: () => act("alert_dismiss", a.id) })))))))
    : el("p", { class: "hint", text: "No alerts for this filter." }));
}

// ---------- skills / plugins ----------
function packageStatus(p, kind) {
  if (kind === "skill") return p.disabled ? "disabled" : (p.status || "");
  return p.status || (p.enabled ? "enabled" : "");
}
function finding(p) {
  const s = typeof p.scan === "string" ? (() => { try { return JSON.parse(p.scan); } catch { return {}; } })() : (p.scan || {});
  return s.max_severity || p.verdict || "";
}
function drawPackages() {
  const kind = $("filter-package").value;
  const raw = kind === "skill" ? ui.state?.skills : ui.state?.plugins;
  const search = $("filter-name").value.toLowerCase();
  const flaggedOnly = $("flagged-only").checked;
  const list = (Array.isArray(raw) ? raw : []).filter((p) => (!search || (p.name || "").toLowerCase().includes(search)) &&
    (!flaggedOnly || /HIGH|CRITICAL|MEDIUM|quarant|block|disabled/i.test(`${finding(p)} ${packageStatus(p, kind)}`)));
  const b = (text, verb, name, danger) => el("button", { class: "btn" + (danger ? " danger" : ""), type: "button", text, onclick: () => act(`${kind}_${verb}`, name) });
  $("packages").replaceChildren(list.length ? el("table", {},
    el("thead", {}, el("tr", {}, ...["Name", "Status", "Finding", "Source", ""].map((t) => el("th", { text: t })))),
    el("tbody", {}, ...list.map((p) => {
      const st = packageStatus(p, kind);
      return el("tr", {},
        el("td", { text: p.name || p.id }),
        el("td", { text: st }),
        el("td", {}, finding(p) ? el("span", { class: `severity ${String(finding(p)).toUpperCase()}`, text: finding(p) }) : ""),
        el("td", { class: "summary", text: String(p.source || p.origin || "").slice(0, 80) }),
        el("td", {}, el("div", { class: "btn-row" },
          /quarant/i.test(st) ? b("restore", "restore", p.name) : null,
          b("block", "block", p.name, true), b("allow", "allow", p.name), b("unblock", "unblock", p.name))));
    })))
    : el("p", { class: "hint", text: "No entries for this filter." }));
}

// ---------- tools, checkpoints, settings ----------
function drawTools() {
  const raw = ui.state?.tools;
  const entries = (Array.isArray(raw) ? raw : []).flatMap((c) => (c.tools || []).map((t) => ({ ...t, connector: c.connector })));
  $("tools").replaceChildren(entries.length ? el("table", {},
    el("thead", {}, el("tr", {}, ...["Tool", "Status", "Reason", ""].map((t) => el("th", { text: t })))),
    el("tbody", {}, ...entries.map((t) => el("tr", {},
      el("td", { text: t.name || t.tool || JSON.stringify(t) }), el("td", { text: t.status || t.action || "" }),
      el("td", { text: t.reason || "" }),
      el("td", {}, el("button", { class: "btn", type: "button", text: "remove from list", onclick: () => act("tool_unblock", t.name || t.tool) }))))))
    : el("p", { class: "hint", text: "The list is empty – no tool is blocked or explicitly allowed." }));
}
function drawCheckpoints() {
  const k = ui.state?.checkpoints || {};
  const n = ui.counts?.per_checkpoint || {};
  const dc = k.defenseclaw || [];
  const own = Object.values(k.own || {}).reduce((a, b) => a + b, 0);
  $("checkpoints").replaceChildren(
    el("p", { class: "hint", text: `${dc.length} events with a DefenseClaw checkpoint · ${own} of your own hooks stay untouched · number = triggers in 24 h` }),
    el("div", { class: "checkpoint-grid" }, ...dc.map((name) => el("div", {}, el("span", { text: name }), el("span", { class: "n", text: num(n[name] || 0) })))));
  $("config").textContent = ui.state?.config || "";
}

// ---------- refresh loop ----------
// A section is only redrawn when its data changed
// (otherwise text selections and click targets would be lost every 10 s).
function ifChanged(name, data, draw) {
  const sig = JSON.stringify(data);
  if (last.get(name) === sig) return;
  last.set(name, sig);
  draw();
}
function drawAll() {
  const z = ui.state || {}, c = ui.counts || {};
  drawHeader();
  ifChanged("tiles", [c.seen, c.allowed, c.would_block, c.blocked, c.unknown, $("filter-verdict").value], drawTiles);
  ifChanged("chart", [c.per_hour, ui.table], drawChart);
  if (last.get("mode") !== JSON.stringify([connector()?.mode, ui.confirming])) drawMode();
  ifChanged("sessions", c.per_session, drawSessions);
  ifChanged("events", [ui.events.map((e) => e.id), [...ui.open], ui.details.size], drawEvents);
  ifChanged("alerts", z.alerts, drawAlerts);
  ifChanged("packages", [z.skills, z.plugins], drawPackages);
  ifChanged("tools", z.tools, drawTools);
  ifChanged("checkpoints", [z.checkpoints, c.per_checkpoint, z.config], drawCheckpoints);
}
let timer;
async function refresh() {
  clearTimeout(timer);
  const q = new URLSearchParams({ session: $("filter-session").value, kind: $("filter-kind").value,
    verdict: $("filter-verdict").value });
  const [z, c, e] = await Promise.allSettled([get("/api/state"), get("/api/counts"), get(`/api/events?${q}`)]);
  if (z.status === "fulfilled") ui.state = z.value;
  if (c.status === "fulfilled") ui.counts = c.value;
  // While a row is open the list stays put (otherwise rows would move under the pointer)
  if (e.status === "fulfilled" && ui.open.size === 0) {
    ui.eventErrors = e.value.errors || [];
    if (!ui.eventErrors.length) ui.events = e.value.events || [];
  }
  $("events-paused").hidden = ui.open.size === 0;
  const errors = [z, c, e].filter((x) => x.status === "rejected").map((x) => x.reason.message);
  // Do not destroy input fields while someone is typing
  const active = document.activeElement;
  if (!(active && active.closest && active.closest(".confirm"))) drawAll();
  if (errors.length) notify("Console unreachable: " + errors.join("; "), true);
  timer = setTimeout(refresh, INTERVAL_MS);
}

drawLegend();
$("toggle-table").addEventListener("click", () => {
  ui.table = !ui.table;
  $("toggle-table").textContent = ui.table ? "as chart" : "as table";
  drawChart();
});
// A result only exists for decisions: another kind clears it, a result selects "Decisions".
$("filter-kind").addEventListener("change", () => {
  if ($("filter-kind").value !== "hook_decision" && $("filter-verdict").value) { $("filter-verdict").value = ""; drawTiles(); }
});
$("filter-verdict").addEventListener("change", () => showVerdict($("filter-verdict").value));
for (const id of ["filter-session", "filter-kind"]) $(id).addEventListener("change", refresh);
for (const id of ["filter-severity", "filter-alert"]) $(id).addEventListener("input", drawAlerts);
for (const id of ["filter-package", "filter-name", "flagged-only"]) $(id).addEventListener("input", drawPackages);
document.querySelectorAll("[data-tool-action]").forEach((b) => b.addEventListener("click", () => {
  const name = $("tool-name").value.trim();
  if (!name) { notify("Please enter a tool name first.", true); return; }
  act(b.dataset.toolAction, name);
}));
refresh();
