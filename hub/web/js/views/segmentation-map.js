// The Segmentation map (canvas-design 6, part B): one firewall's zones in lanes by role (Internet | Edge | Users |
// Servers | Core | Unclassified), the assets placed in them (chips, or type clusters above 12), the traffic its pass
// rules may allow between zones (an approximation: block rules, rule order and NAT are not evaluated), the segmentation
// policy's possible violations and open findings as overlays, and guarded firewall changes: operators draw an arrow
// from zone to zone (or click-click, or "Allow traffic to..." in a zone's details) to open the Change panel, or press
// Delete on an edge to propose disabling its rules. Every change is a proposal an administrator who did not propose it
// approves on the Approvals page; this map has no Approve button (S5). Zone, rule, alias and interface names come from
// devices: SVG text is set with textContent, HTML through html`` (escaped).
// Mounted by views/integration.js as the "Segmentation" tab: mount(container, ctx, {params}) -> {dispose, select}.
// Deep links: #/integration/segmentation/zone/<zone id>, /edge/<edge id>, /change/<change id>.
import { del, get, onEvent, patch, post, put } from "../api.js";
import { session } from "../auth.js";
import { openChangePanel } from "../changepanel.js";
import {
  OP_LABEL, WAITING, changeSummary, countdown, lifecycle, openChange, reasonText, rollbackLabel, startTicker, statusBadge, statusLabel,
} from "../netchanges.js";
import { actions, badge, can, confirmDialog, dateTime, debounce, emptyState, field, html, icon, modal, options, setHTML, timeAgo, toast } from "../ui.js";
import { createCanvas } from "../canvas/engine.js";
import { segmentationFixture } from "../canvas/fixture.js";
import { planMove } from "../canvas/lanes.js";
import { layoutStore } from "../canvas/layout.js";
import {
  CHANGE_WORD, GUTTER, INTERNET, LANES, MATRIX_MAX, OPEN, PAD, ROLES, ROLE_COLOR, ROLE_LABEL, TYPE_GLYPH, TYPE_LABEL, buildModel, canAllow,
  canConnect, chipBox, compareZones, controlsOf, edgeChips, edgeName, exposureText, findingsText, headHeight, isUnconfirmed, matrix,
  orderedZones, pairEdges, roleGlyph, ruleChange, servicesText, zoneLabel, zoneName,
} from "../canvas/segmentation-model.js";
import { font, measure } from "../canvas/text.js";
import { openImport } from "./tools.js";

const VIEW = "segmentation";
const enc = encodeURIComponent;
const PREFS = `hub.canvas.${VIEW}`;
const REFETCH = ["segmentation", "firewall_change", "network_snapshot", "network_settings", "asset", "asset_removed", "vulnerability", "connection",
  "tool", "tool_removed", "approval", "maintenance_window"];
const LANE_TITLE = Object.fromEntries(LANES.map((l) => [l.id, l.title]));
const NAME_FONT = font(13.5, 650), SUB_FONT = font(11.5, 500), CHIP_FONT = font(11.5, 550), PILL_FONT = font(10.5, 650);
const SEV = ["critical", "high", "medium", "low"];
const ASSET_LIMIT = 60; // assets listed in a zone's details (the List view has them all)
const plural = (n, word, many = `${word}s`) => `${n} ${n === 1 ? word : many}`;

const readPref = (key, fallback) => {
  try { const v = JSON.parse(localStorage.getItem(`${PREFS}.${key}`)); return v ?? fallback; } catch { return fallback; }
};
const writePref = (key, value) => { try { localStorage.setItem(`${PREFS}.${key}`, JSON.stringify(value)); } catch { /* private mode */ } };

/** The firewall a deep link points at: zone "z:<tool>:<native>", edge "zp:z:<tool>:...". */
function firewallOf(kind, ref) {
  const z = kind === "edge" ? String(ref || "").replace(/^zp:/, "") : String(ref || "");
  if (!z.startsWith("z:") || z.startsWith(`${INTERNET}>`) || z === INTERNET) return null;
  return z.split(":")[1] || null;
}

export function mount(container, ctx, { params = [] } = {}) {
  const debug = (() => { try { return localStorage.getItem("hub.canvas.debug") === "1" && !!localStorage.getItem("hub.canvas.fixture"); } catch { return false; } })();
  const operator = can("operator") && !debug;
  const admin = can("admin") && !debug;
  let data = null; // GET /api/segmentation
  let changes = []; // GET /api/segmentation/changes?firewall= (newest first)
  let devices = null; // GET /api/network/devices, read when no firewall is on the map
  let model = { items: new Map(), edges: new Map(), index: new Map(), counts: { zones: 0, assets: 0, unplaced: 0, edges: 0, shown: 0, violations: 0, pending: 0 }, traffic: "all" };
  const prefs = { traffic: "auto", compliance: true, vulns: true, ...readPref("filters", {}) };
  let firewall = readPref("firewall", null);
  let find = "";
  let disposed = false;
  let pendingLink = params.length ? params : null;
  let trayTouched = false;
  let menu = null; // the open View or Changes popover
  let listWired = false;

  setHTML(container, html`<div data-part="map-host"></div>`);
  const host = container.querySelector('[data-part="map-host"]');
  const store = layoutStore(VIEW, { apply: (doc) => canvas?.replaceLayout(doc) });

  const fw = () => data?.firewalls.find((f) => f.tool_id === data.selected) || null;
  const fwName = () => fw()?.name || data?.selected || "the firewall";
  const writable = () => operator && !!fw()?.writable;
  const item = (id) => model.items.get(id);
  const label = (id) => item(id)?.label || zoneLabel((data?.zones || []).find((z) => z.id === id)) || id;
  const changeOf = (id) => changes.find((c) => c.id === id) || (data?.changes || []).find((c) => c.id === id) || null;

  // ---------- drawing ----------
  function pills(g, c, list, right, y) {
    let x = right;
    for (const [text, tone] of list) {
      const shown = c.ellipsize(text, 120, PILL_FONT);
      const w = Math.ceil(measure(shown, PILL_FONT)) + 14;
      x -= w;
      const p = c.el("g", { class: `bdg ${tone}`, transform: `translate(${x} ${y})` }, g);
      c.el("rect", { width: w, height: 16, rx: 8 }, p);
      c.txt(p, shown, { x: 7, y: 11.5 });
      x -= 4;
    }
    return x;
  }

  function assetChip(g, c, box, glyph, text, worst, cls) {
    const chip = c.el("g", { class: `achip ${cls}`, transform: `translate(${box.x} ${box.y})` }, g);
    c.el("rect", { width: box.w, height: box.h, rx: 11 }, chip);
    c.use(chip, glyph, 6, 4, 14);
    c.txt(chip, c.ellipsize(text, box.w - (worst ? 40 : 30), CHIP_FONT), { x: 24, y: 15 });
    if (worst) c.el("circle", { class: `sev-dot ${worst}`, cx: box.w - 11, cy: 11, r: 4.5 }, chip);
  }

  function drawZone(it, item, c) {
    const z = it.zone;
    const color = ROLE_COLOR[z.role] || "unknown";
    const g = c.el("g", { class: `zone-box c-${color}` }, item); // carries the role colour (--zone-c) to everything inside
    c.el("rect", { class: `node zone${z.role === "unknown" ? " unknown" : ""}`, width: c.w, height: c.h, rx: 12 }, g);
    if (prefs.vulns) {
      const counts = SEV.map((s) => z.vuln?.[s] || 0);
      const total = counts.reduce((a, b) => a + b, 0);
      if (total) {
        const strip = c.el("g", { class: "sev-strip" }, g);
        let x = 12;
        const span = c.w - 24;
        SEV.forEach((s, i) => {
          if (!counts[i]) return;
          const w = Math.max(4, (span * counts[i]) / total);
          c.el("rect", { class: s, x, y: 3, width: w, height: 4, rx: 2 }, strip);
          x += w;
        });
      }
    }
    c.el("rect", { class: "zone-tile", x: 10, y: 12, width: 28, height: 28, rx: 8 }, g);
    c.use(g, roleGlyph(z.role), 15, 17, 18, { class: "glyph zone-glyph" });
    const count = `${it.assets} asset${it.assets === 1 ? "" : "s"}`;
    const countW = Math.ceil(measure(count, SUB_FONT));
    c.txt(g, c.ellipsize(it.label, c.w - 58 - countW, NAME_FONT), { class: "name", x: 46, y: 25 });
    c.txt(g, count, { class: "sub", x: c.w - 10, y: 25, "text-anchor": "end" });
    const nets = (z.subnets || []).length ? `${z.subnets[0]}${z.subnets.length > 1 ? ` +${z.subnets.length - 1}` : ""}` : z.id === INTERNET ? "outside your networks" : "no networks";
    const badges = [];
    if (isUnconfirmed(z) && z.id !== INTERNET) badges.push(["not confirmed", "warn"]);
    if ((z.same_subnet_as || []).length) badges.push(["shared subnet", "info"]);
    const left = pills(g, c, badges, c.w - 8, 33);
    c.txt(g, c.ellipsize(`${ROLE_LABEL[z.role] || z.role} · ${nets}`, left - 52, SUB_FONT), { class: "sub", x: 46, y: 45 });
    if (it.vulnLine) c.txt(g, c.ellipsize(it.vulnLine, c.w - 56, font(11, 650)), { class: "sevline", x: 46, y: 61 });
    const head = headHeight(!!it.vulnLine);
    c.el("line", { class: "head-line", x1: 0, y1: head, x2: c.w, y2: head }, g);
    const ct = it.contents;
    if (ct.mode === "empty") {
      c.txt(g, z.id === INTERNET ? "No external assets" : "No assets placed here", { class: "sub empty-line", x: PAD, y: head + 16 });
    } else if (ct.mode === "chips") {
      ct.chips.forEach((a, i) => assetChip(g, c, chipBox(i, head), TYPE_GLYPH[a.type] || "box", a.name, a.worst,
        `${a.badges.includes("manual") ? "manual" : ""}${a.warning ? " warn" : ""}${a.badges.includes("external") ? " ext" : ""}`));
    } else {
      ct.clusters.forEach((k, i) => assetChip(g, c, chipBox(i, head), TYPE_GLYPH[k.type] || "box", `${TYPE_LABEL[k.type] || k.type} ×${k.count}`, k.worst, "cluster"));
    }
  }

  function signature(it) {
    const z = it.zone;
    return [it.label, z.role, z.role_source, (z.subnets || []).join(","), (z.same_subnet_as || []).length, it.assets, it.vulnLine, prefs.vulns,
      SEV.map((s) => z.vuln?.[s] || 0).join(","), JSON.stringify(it.contents)].join("|");
  }

  const nearSelection = (e) => {
    const sel = canvas?.selection;
    return !!sel && (sel === e.id || e.from.id === sel || e.to.id === sel);
  };

  function edgeStyle(e) {
    const chips = edgeChips(e, prefs);
    if (e.kind === "change") {
      return { cls: `k-change st-${e.change.status}`, marker: "accent", arrow: "to", chip: chips.chip, chipSelected: chips.selected, glyph: "clock", width: 2 };
    }
    const bad = e.violations.length > 0;
    const cls = ["k-traffic", `v-${e.verdict}`, bad ? "st-violation" : "", prefs.compliance && !bad && !nearSelection(e) ? "compliant" : "",
      e.disabling ? "st-disabling" : e.pending.length ? "st-pending" : "", prefs.vulns && e.exposure ? "exposed" : ""].filter(Boolean).join(" ");
    return {
      cls, arrow: e.arrow, width: e.width, chip: chips.chip, chipSelected: chips.selected,
      marker: e.disabling || e.verdict === "forbidden" ? "bad" : e.verdict === "restricted" ? "proposed" : "flow",
      under: bad ? "halo" : e.any ? "hatch" : null,
      glyph: e.disabling ? "x" : e.pending.length ? "clock" : bad && prefs.compliance ? "alert" : prefs.vulns && e.exposure ? "bug" : null,
    };
  }

  // ---------- names and tooltips ----------
  const nameOf = (id) => {
    const it = item(id);
    if (it) return zoneName(it);
    const e = model.edges.get(id);
    return e ? edgeName(e, label) : id;
  };

  function tipOf(id) {
    const it = item(id);
    if (it) {
      const z = it.zone;
      const f = findingsText(z.vuln);
      return html`<b>${it.label}</b>${it.label !== z.name && z.name ? html` <span class="faint">(${z.name})</span>` : ""}
        <div class="muted">${ROLE_LABEL[z.role] || z.role} zone${isUnconfirmed(z) && z.id !== INTERNET ? " - role not confirmed" : ""}</div>
        <div>${(z.subnets || []).join(", ") || (z.id === INTERNET ? "Every address outside the firewall's networks" : "No networks")}</div>
        <div>${plural(it.assets, "asset")}${f ? ` · ${f}` : ""}</div>`;
    }
    const e = model.edges.get(id);
    if (!e) return null;
    if (e.kind === "change") {
      const c = changeOf(e.change.id) || e.change;
      return html`<b>${OP_LABEL[c.op] || c.op}: ${label(e.from.id)} &rarr; ${label(e.to.id)}</b><div>${statusBadge(c.status)} <span class="faint">${c.id}${c.proposed_by ? ` by ${c.proposed_by}` : ""}</span></div>`;
    }
    const x = exposureText(e.exposure);
    return html`<b>${label(e.from.id)} &rarr; ${label(e.to.id)}${e.backward ? " (and back)" : ""}</b>
      <div>${servicesText(e.raw, 4)} · ${plural(e.rules, "rule")}</div>
      ${e.violations.length ? html`<div class="bad-text">May violate ${controlsOf(e.violations).join(", ")}</div>` : ""}
      ${x ? html`<div class="warn-text">${x} on allowed ports</div>` : ""}
      ${e.disabling ? html`<div>Disable ${CHANGE_WORD[e.disabling.status] || e.disabling.status} (${e.disabling.id})</div>` : ""}
      <div class="faint">May allow: block rules, rule order and NAT are not evaluated.</div>`;
  }

  // ---------- canvas ----------
  const canvas = createCanvas(host, {
    view: VIEW, label: "Segmentation map", roledescription: "segmentation map", lanes: LANES, gutter: GUTTER, detour: true,
    help: "Segmentation map. Arrow keys move between zones, Enter opens the details, E moves along a zone's allowed traffic, C proposes allowing traffic to another zone (operators, when device changes are on), Delete on allowed traffic proposes disabling its rules, L shows the same information as tables, question mark lists every shortcut.",
    permissions: { move: operator, connect: false },
    helpRows: [["C", "Allow traffic from the focused zone to another one (operators, when device changes are on): arrows choose the zone, Enter opens the Change panel"],
      ["/", "Find a zone"]],
    bar: html`
      <select class="input-sm cv-fw" data-part="seg-fw" aria-label="Firewall shown" hidden></select>
      <button type="button" class="btn sm" data-act="seg-view" aria-expanded="false" aria-haspopup="true">${icon("sliders")}View</button>
      <input type="search" class="cv-find" data-part="seg-find" placeholder="Find a zone..." aria-label="Find a zone">
      <button type="button" class="btn sm" data-act="seg-changes" aria-expanded="false" aria-haspopup="true">${icon("flow")}Changes<span class="cv-count" data-part="seg-ccount"></span></button>
      <button type="button" class="btn sm" data-act="seg-refresh" data-min-role="operator" title="Read the firewall again now">${icon("refresh")}Refresh</button>
      <button type="button" class="btn sm" data-act="seg-policy" title="The segmentation policy the edges are checked against">${icon("shield")}Policy</button>
      <button type="button" class="btn sm" data-act="seg-reset" data-min-role="operator" title="Put every zone back in its default place, for everyone">${icon("undo")}Reset arrangement</button>`,
    adapter: {
      size: (it) => ({ w: it.w, h: it.h }),
      lane: (it) => it.lane,
      compare: compareZones,
      signature,
      draw: drawZone,
      edgeStyle,
      name: nameOf,
      role: (id) => (item(id) ? "zone" : model.edges.get(id)?.kind === "change" ? "proposed change" : "allowed traffic"),
      tip: tipOf,
      grips: (it) => (canAllow(it.zone) ? ["right"] : []),
      canConnect: (a, b) => canConnect(model.items, a, b),
      canMove: (it) => ({ lanes: [it.lane] }), // the lane is the role: zones only reorder within it
      onConnect: (a, b) => allowPanel(a, b),
      onMove: (id, { changes: orders }) => store.move(Object.fromEntries(Object.entries(orders).map(([x, order]) => [x, { order }]))),
      onSelect: selected,
      onOpen: (id) => { selected(id); canvas.showInspector(true); setTimeout(() => canvas.inspector.querySelector("button, a, select, input")?.focus(), 0); },
      onDelete: deleteKey,
      onKey(k) {
        if (k === "/") { canvas.shell.querySelector('[data-part="seg-find"]').focus(); return true; }
        return false;
      },
      onUndo: () => store.undo(),
      onRedo: () => store.redo(),
      onEscape: () => closeMenu(),
      connectHint: () => (operator ? `Changes cannot be proposed now: ${reasonText(fw()?.reason)}` : "Operators propose firewall changes"),
      summary: () => `${model.counts.zones} zones, ${model.counts.assets} assets placed, ${model.counts.shown} of ${model.counts.edges} allowed traffic connections shown`
        + `${model.counts.pending ? `, ${plural(model.counts.pending, "proposed change")}` : ""}`,
      list: renderList,
    },
  });
  const stopTicker = startTicker(canvas.shell);
  const tray = document.createElement("details");
  tray.className = "seg-tray";
  tray.hidden = true;
  canvas.shell.querySelector(".canvas-stage").append(tray);
  tray.addEventListener("toggle", () => { if (tray.dataset.auto !== "1") trayTouched = true; tray.dataset.auto = ""; });

  // ---------- data ----------
  function rebuild() {
    if (!data) return;
    model = buildModel(data, { traffic: prefs.traffic, selection: canvas.selection, overlays: prefs });
    canvas.setPermissions({ move: operator && !!data.selected, connect: writable() });
    canvas.update(model, store.doc);
    applyFilter();
    notices();
    drawBar();
    drawTray();
    if (canvas.selection) renderInspector(canvas.selection);
    if (canvas.listView) renderList(canvas.list);
    if (menu?.dataset.kind === "changes") fillChanges(menu);
  }

  function drawBar() {
    const sel = canvas.shell.querySelector('[data-part="seg-fw"]');
    const list = data?.firewalls || [];
    sel.hidden = list.length < 2;
    if (list.length > 1) {
      setHTML(sel, html`${list.map((f) => html`<option value="${f.tool_id}" ${f.tool_id === data.selected ? "selected" : ""}>${f.name}</option>`)}`);
    }
    const open = (data?.changes || []).filter((c) => OPEN.includes(c.status)).length;
    canvas.shell.querySelector('[data-part="seg-ccount"]').textContent = open ? ` (${open})` : "";
  }

  function drawTray() {
    const list = data?.unplaced || [];
    tray.hidden = !data?.selected || !list.length;
    if (tray.hidden) return;
    const was = tray.open;
    setHTML(tray, html`<summary>${icon("box")}Unplaced assets (${list.length})</summary>
      <p class="faint" style="padding:6px 12px 0;font-size:12px">No address of these is inside one of ${fwName()}'s networks, or they have only hostnames (Atrium does not look names up).</p>
      <ul>${list.slice(0, 100).map((a) => html`<li><span class="grow" style="min-width:0;overflow-wrap:anywhere"><a href="#/assets/${enc(a.id)}">${a.name}</a>
        <span class="faint">- ${a.reason}</span></span>${operator ? html`<button type="button" class="btn sm" data-act="tray-place" data-id="${a.id}">Place...</button>` : ""}</li>`)}
        ${list.length > 100 ? html`<li class="faint">and ${list.length - 100} more (List view)</li>` : ""}</ul>`);
    const auto = !trayTouched && !(data.assets || []).length;
    if (trayTouched ? was : auto) { tray.dataset.auto = "1"; tray.open = true; }
  }

  function noticeRow(iconName, body, tone = "", button = "") {
    return html`<div class="seg-note ${tone}">${icon(iconName)}<div class="grow">${body}</div>${button}</div>`;
  }

  function notices() {
    const f = fw();
    if (!f) return canvas.setNotice(null);
    const rows = [];
    let tone = "";
    for (const c of changes.filter((x) => x.status === "applying" || x.status === "verifying")) {
      const failed = c.status === "verifying" && c.result && !c.result.ok;
      if (failed) tone = "bad";
      const checks = (c.verification || []).map((v) => html`<span class="seg-check ${v.ok === true ? "ok" : v.ok === false ? "bad" : ""}">${icon(v.ok === true ? "check" : v.ok === false ? "x" : "clock")}${String(v.name || "").replace(/_/g, " ")}</span>`);
      rows.push(noticeRow(failed ? "alert" : "activity", html`<b>${c.status === "applying" ? `Applying change ${c.id} on ${f.name}` : failed
        ? `Verification failed on ${f.name}: waiting for the device's own rollback` : `Applying change ${c.id} on ${f.name}, confirming connectivity`}</b>
        ${c.rollback_until ? html` (${countdown(c.rollback_until)})` : ""}${checks.length ? html`<div class="seg-checks">${checks}</div>` : ""}`, failed ? "bad" : "",
      html`<button type="button" class="btn sm" data-act="note-change" data-id="${c.id}">Open</button>`));
    }
    if (f.snapshot?.stale) {
      tone ||= "warn";
      rows.push(noticeRow("clock", html`<b>Firewall data is from ${timeAgo(f.snapshot.read_at)}.</b> <span class="muted">Changes are proposed only on a recent read.</span>`, "warn",
        operator ? html`<button type="button" class="btn sm" data-act="seg-refresh">${icon("refresh")}Refresh</button>` : ""));
    }
    if (!f.writable) {
      const off = f.reason === "guardrail";
      rows.push(noticeRow("lock", html`<b>Read-only:</b> ${off ? "device changes are off." : `${reasonText(f.reason)}.`}
        ${off ? (admin ? html`An administrator can turn them on in <a href="#/settings">Settings &gt; Network changes</a>.` : "An administrator can turn them on in Settings.") : ""}
        ${!operator && !debug ? html`<span class="muted">Operators propose changes; administrators approve them.</span>` : ""}`));
    } else if (!operator) {
      rows.push(noticeRow("lock", html`<b>Read-only for you.</b> <span class="muted">Operators propose firewall changes; an administrator approves each one.</span>`));
    } else {
      rows.push(noticeRow("flow", html`<b>Changes are on.</b> <span class="muted">Drag from a zone's handle to another zone (or press C) to propose allowing traffic; select allowed traffic and press Delete to propose disabling rules. An administrator approves each change.</span>`));
    }
    if (!(data.assets || []).length) {
      rows.push(noticeRow("box", html`Assets appear in a zone when one of their addresses is in its subnet. <a href="#/assets">Assets</a>`));
    }
    if (find && ![...model.items.keys()].some(matches)) {
      tone ||= "warn";
      rows.push(noticeRow("search", html`No zones match "${find}".`, "warn", html`<button type="button" class="btn sm" data-act="seg-clear-find">Clear filter</button>`));
    }
    if (prefs.traffic !== "all" && model.traffic === "focus" && model.counts.shown < model.counts.edges) {
      rows.push(noticeRow("sliders", html`<span class="muted">Showing ${model.counts.shown} of ${model.counts.edges} allowed-traffic connections: the selected zone's, possible violations and proposed changes.</span>`, "",
        html`<button type="button" class="btn sm" data-act="seg-show-all">Show all</button>`));
    }
    rows.push(noticeRow("alert", html`<span class="muted">${(data.evaluation?.notes || []).join(" ") || "Approximate evaluation."}</span>`, "faint"));
    canvas.setNotice(html`<div class="seg-notes">${rows}</div>`, tone);
  }

  let loading = null;
  async function fetchAll() {
    let next;
    try {
      next = await get(`/segmentation${firewall ? `?firewall=${enc(firewall)}` : ""}`);
    } catch (err) {
      if (err.status !== 404 || !firewall) throw err;
      firewall = null; // that firewall is gone: show the default one
      writePref("firewall", null);
      next = await get("/segmentation");
    }
    const [list, devs] = await Promise.all([
      next.selected ? get(`/segmentation/changes?firewall=${enc(next.selected)}&limit=40`).catch(() => ({ changes: [] })) : { changes: [] },
      next.firewalls.length ? null : get("/network/devices").catch(() => ({ devices: [] })),
    ]);
    return { next, changes: list.changes || [], devices: devs?.devices || null };
  }

  async function load() {
    if (debug) {
      data = segmentationFixture();
      store.set(data.layout);
      overlay(null);
      return rebuild();
    }
    loading ??= fetchAll().finally(() => { loading = null; });
    let got;
    try {
      got = await loading;
    } catch (err) {
      if (disposed) return;
      if (!data) overlay(emptyState("alert", "Could not load the segmentation map", err.message, html`<button type="button" class="btn" data-act="seg-retry">Retry</button>`));
      else toast(`The segmentation map could not be refreshed: ${err.message}`, "warn");
      return;
    }
    if (disposed) return;
    const prev = canvas.selection;
    const prevName = prev ? nameOf(prev).split(", selected")[0] : "";
    const prevChange = prev ? watchedChange(prev) : null;
    const before = prev ? statusOf(prev) : null;
    data = got.next;
    changes = got.changes;
    devices = got.devices;
    store.set(data.layout);
    if (!data.firewalls.length) {
      model = buildModel({ zones: [], edges: [] });
      canvas.update(model, store.doc);
      canvas.setNotice(null);
      tray.hidden = true;
      drawBar();
      return overlay(emptyView());
    }
    overlay(null);
    rebuild();
    const after = canvas.selection ? statusOf(canvas.selection) : null;
    if (before && after && before !== after) canvas.announce(`${nameOf(canvas.selection)}`);
    const done = prevChange && changeOf(prevChange);
    const finished = done && !OPEN.includes(done.status) ? done : null;
    const gone = prev && !model.items.has(prev) && !model.edges.has(prev);
    if (finished) {
      const said = `Change ${finished.id} ${statusLabel(finished.status)}`;
      toast(`Change ${finished.id}: ${statusLabel(finished.status)}`, finished.status === "applied" ? "ok" : finished.status === "failed" ? "bad" : "warn");
      // a finished change's ghost edge left the map: select the traffic it changed, announced with the outcome
      const drawn = gone && finished.edge && model.index.get(finished.edge);
      if (drawn) selectEdge(drawn, said);
      else canvas.announce(said);
    } else if (gone) {
      canvas.announce(`${prevName.split(", ")[0]}: no longer on the map`);
    }
    if (pendingLink) followLink(pendingLink);
  }

  /** The open change the selection stands for: a ghost edge's change, or the disable / revert pending on selected traffic. */
  function watchedChange(id) {
    const e = model.edges.get(id);
    if (!e) return null;
    return e.kind === "change" ? e.change.id : e.disabling?.id || e.pending?.[0]?.id || null;
  }
  const refetch = debounce(load, 1000);
  const statusOf = (id) => {
    const e = model.edges.get(id);
    return e?.kind === "change" ? changeOf(e.change.id)?.status || e.change.status : e?.disabling?.status || null;
  };

  function emptyView() {
    const net = (devices || []);
    const unread = net.filter((d) => !d.snapshot);
    const hosts = net.filter((d) => d.snapshot && d.kind === "host");
    if (!net.length) {
      return html`<div class="card" style="max-width:560px">${emptyState("shield", "No firewall connected",
        "Import your firewall, router or switch and set up its connection: its zones, the assets in them and the traffic its rules allow appear here. Atrium reads OPNsense, pfSense, MikroTik RouterOS, FortiGate, PAN-OS and Cisco IOS-XE devices; host firewalls appear in the Network app.",
        html`<button type="button" class="btn primary" data-act="seg-import" data-min-role="operator">${icon("plus")}Import tool</button> <a class="btn" href="#/network">${icon("network")}Network app</a>`)}</div>`;
    }
    if (unread.length) {
      return html`<div class="card" style="max-width:620px">${emptyState("shield", "Not read yet",
        "Test the firewall's connection and run its network data flow to read its interfaces and rules.")}
        <div class="stack" style="gap:6px;margin-top:4px">${unread.map((d) => html`<div class="row seg-dev" style="justify-content:space-between;flex-wrap:wrap">
          <span><b>${d.name}</b> <span class="faint">${d.connection?.state === "failing" ? "connection test failing" : d.connection?.state === "ok" ? "connected" : "not tested"}${d.flow ? "" : ", no network data flow (approve it in Approvals)"}</span></span>
          <span class="row" style="gap:6px" data-min-role="operator"><button type="button" class="btn sm" data-act="dev-test" data-id="${d.tool_id}">${icon("activity")}Test</button>
            <button type="button" class="btn sm" data-act="dev-refresh" data-id="${d.tool_id}">${icon("refresh")}Read now</button></span></div>`)}</div></div>`;
    }
    return html`<div class="card" style="max-width:560px">${emptyState("shield", "No firewall to draw",
      `${hosts.length ? `${plural(hosts.length, "host firewall")} protect${hosts.length === 1 ? "s" : ""} only its own machine, so ${hosts.length === 1 ? "it is" : "they are"} not drawn here.` : ""} Connect a firewall, router or switch to see zones and the traffic between them.`,
      html`<a class="btn" href="#/network">${icon("network")}Network app</a>`)}</div>`;
  }

  function overlay(content) {
    let o = canvas.shell.querySelector(".cv-overlay");
    if (!content) return o?.remove();
    if (!o) {
      o = document.createElement("div");
      o.className = "cv-overlay";
      canvas.shell.querySelector(".canvas-stage").append(o);
    }
    setHTML(o, content);
  }

  // live updates (canvas-design 4.8): subscribed before the first fetch; anything relevant re-fetches once (debounced)
  let ready = false;
  let missed = false;
  const offs = [];
  if (!debug) {
    offs.push(onEvent(REFETCH, () => (ready ? refetch() : (missed = true))));
    offs.push(onEvent("canvas_layout", (e) => { if (e.data?.view === VIEW) store.remote(e.data.version); }));
  }
  const onReconnect = () => load();
  const onVisible = () => { if (document.visibilityState === "visible") load(); };
  window.addEventListener("atrium:events-reconnected", onReconnect);
  document.addEventListener("visibilitychange", onVisible);
  const timer = setInterval(() => { if (document.visibilityState === "visible" && !debug) load(); }, 120000);

  overlay(html`<div class="empty faint">Loading map...</div>`);
  (async () => {
    // a deep link to another firewall's zone, edge or change shows that firewall
    if (pendingLink && !debug) {
      const [kind, ref] = pendingLink;
      if (kind === "change" && ref) firewall = (await get(`/segmentation/changes/${enc(ref)}`).catch(() => null))?.firewall || firewall;
      else firewall = firewallOf(kind, ref) || firewall;
    }
    await load();
    ready = true;
    if (missed) load();
  })();
  if (innerWidth < 560) canvas.setList(true);

  // ---------- selection, inspector, deep links ----------
  function linkFor(id) {
    if (!id) return "#/integration/segmentation";
    if (id.startsWith("chg:")) return `#/integration/segmentation/change/${enc(id.slice(4))}`;
    return model.items.has(id) ? `#/integration/segmentation/zone/${enc(id)}` : `#/integration/segmentation/edge/${enc(id)}`;
  }

  /** Select an edge the focus filter may not draw: rebuild with it as the selection so it is kept. `note` is announced
   *  together with the selection (one live-region message, so the second does not replace the first). */
  function selectEdge(id, note = "") {
    if (!model.edges.has(id) && data) {
      model = buildModel(data, { traffic: prefs.traffic, selection: id, overlays: prefs });
      canvas.update(model, store.doc);
    }
    setTimeout(() => {
      if (!model.edges.has(id)) return toast("That connection is not on the map", "warn");
      canvas.select(id, { reveal: true, quiet: !!note });
      if (note) canvas.announce(`${note}. ${nameOf(id)}, selected`);
      canvas.showInspector(true);
    }, 30);
  }

  function followLink(p) {
    pendingLink = null;
    const [kind, ref] = p;
    if (!kind || !ref) return;
    if (kind === "zone") {
      if (!model.items.has(ref)) return toast("That zone is not on the map (it may belong to another firewall or be gone)", "warn");
      canvas.select(ref, { reveal: true });
      return canvas.showInspector(true);
    }
    if (kind === "edge") return selectEdge(model.index.get(ref) || ref);
    if (kind === "change") {
      if (model.edges.has(`chg:${ref}`)) { canvas.select(`chg:${ref}`, { reveal: true }); return canvas.showInspector(true); }
      const c = changeOf(ref);
      const drawn = c?.edge && model.index.get(c.edge);
      if (drawn && OPEN.includes(c.status)) return selectEdge(drawn);
      openChange(ref, { deviceName: fwName() }).catch((err) => toast(err.message, "bad"));
    }
  }

  function selected(id) {
    if (location.hash.startsWith("#/integration/segmentation")) history.replaceState(null, "", linkFor(id));
    if (model.traffic === "focus") rebuild(); // the focus filter follows the selection
    if (!id) return canvas.showInspector(false);
    renderInspector(id);
    canvas.showInspector(true);
  }

  const head = (title, sub, tile = "") => html`<div class="cv-insp-head">${tile}<div style="min-width:0"><h2>${title}</h2>${sub ? html`<div class="faint" style="font-size:12px">${sub}</div>` : ""}</div>
    <button type="button" class="icon-btn sm" data-act="insp-close" aria-label="Close details">${icon("x")}</button></div>`;

  function renderInspector(id) {
    const root = canvas.inspector;
    const active = document.activeElement && root.contains(document.activeElement) ? document.activeElement : null;
    const again = active?.dataset.act ? `[data-act="${CSS.escape(active.dataset.act)}"]${active.dataset.id ? `[data-id="${CSS.escape(active.dataset.id)}"]` : ""}` : null;
    const it = item(id);
    const e = model.edges.get(id);
    let body;
    if (it) body = zonePanel(it);
    else if (e?.kind === "change") body = changePanel(e);
    else if (e) body = trafficPanel(e);
    else return canvas.showInspector(false);
    setHTML(root, body);
    if (again) root.querySelector(again)?.focus();
  }

  const zoneTile = (z) => html`<span class="seg-tile c-${ROLE_COLOR[z.role] || "unknown"}" aria-hidden="true">${icon(roleGlyph(z.role))}</span>`;
  const sevBadges = (v) => html`${SEV.filter((s) => v?.[s]).map((s) => html`<span class="sev ${s}">${s} ${v[s]}</span> `)}${v?.overdue ? badge(`${v.overdue} overdue`, "bad") : ""}`;
  const edgesOf = (zid) => {
    const { pairs } = pairEdges(data?.edges || []);
    return pairs.filter((p) => p.forward.source === zid || p.forward.target === zid);
  };
  const assetsIn = (zid) => (data?.assets || []).filter((a) => a.zone === zid);

  function zonePanel(it) {
    const z = it.zone;
    const roleHow = z.role_source === "manual" ? "set by an administrator" : z.role_source === "builtin" ? "built in" : z.role === "unknown" ? "not recognised from the name" : "guessed from the name";
    const pairs = edgesOf(z.id);
    const assets = assetsIn(z.id);
    const others = (data.zones || []).filter((x) => x.id !== z.id && canAllow(x));
    return html`${head(it.label, `${ROLE_LABEL[z.role] || z.role} zone · ${fwName()}`, zoneTile(z))}
      <div class="row" style="gap:6px;margin-bottom:10px">${isUnconfirmed(z) && z.id !== INTERNET ? badge("role not confirmed", "warn") : z.role_source === "manual" ? badge("role confirmed", "ok") : ""}
        ${z.vlan ? badge(`VLAN ${z.vlan}`) : ""}${z.kind && z.kind !== "pseudo" ? badge(z.kind) : ""}</div>
      <dl class="kv">
        <dt>Role</dt><dd>${ROLE_LABEL[z.role] || z.role} <span class="faint">(${roleHow})</span></dd>
        ${z.label && z.name && z.label !== z.name ? html`<dt>Device name</dt><dd>${z.name}</dd>` : ""}
        <dt>Networks</dt><dd>${(z.subnets || []).length ? html`<div class="tag-list">${z.subnets.map((s) => html`<span class="badge mono">${s}</span>`)}</div>`
          : html`<span class="muted">${z.id === INTERNET ? "every address outside the firewall's networks" : "none"}</span>`}</dd>
        ${(z.interfaces || []).length ? html`<dt>Interfaces</dt><dd class="mono" style="overflow-wrap:anywhere">${z.interfaces.join(", ")}</dd>` : ""}
        ${(z.same_subnet_as || []).length ? html`<dt>Same subnet</dt><dd>${z.same_subnet_as.map((x) => html`<div class="mono faint" style="overflow-wrap:anywhere">${x}</div>`)}</dd>` : ""}
        <dt>Assets</dt><dd>${it.assets}</dd>
        <dt>Findings</dt><dd>${findingsText(z.vuln) ? sevBadges(z.vuln) : html`<span class="muted">no open findings</span>`}</dd></dl>
      <div class="cv-insp-actions">
        ${admin && z.id !== INTERNET ? html`<button type="button" class="btn sm" data-act="insp-role">${icon("edit")}${isUnconfirmed(z) ? "Confirm role..." : "Change role..."}</button>` : ""}
        ${writable() && canAllow(z) && others.length ? html`<button type="button" class="btn sm primary" data-act="insp-allow">${icon("flow")}Allow traffic to...</button>` : ""}
        ${operator ? html`<button type="button" class="btn sm" data-act="insp-move" data-dir="up">Move up</button><button type="button" class="btn sm" data-act="insp-move" data-dir="down">Move down</button>` : ""}
        ${z.firewall ? html`<a class="btn sm" href="#/network/${enc(z.firewall)}/interfaces">${icon("network")}Network app</a>` : ""}</div>
      ${operator && !writable() && canAllow(z) ? html`<p class="faint" style="font-size:12px">Proposing changes: ${reasonText(fw()?.reason)}.</p>` : ""}
      <div class="cv-insp-section"><h3>Allowed traffic (${pairs.length})</h3>
        ${pairs.length ? html`<div class="cv-edge-list">${pairs.map((p) => {
          const out = p.forward.source === z.id;
          const other = out ? p.forward.target : p.forward.source;
          const vs = [p.forward, p.backward].filter(Boolean).flatMap((x) => x.violations || []);
          return html`<button type="button" class="menu-item" data-act="insp-select" data-id="${p.id}">${icon(p.backward ? "refresh" : out ? "arrow" : "download")}
            <span style="min-width:0;overflow-wrap:anywhere">${p.backward ? "with" : out ? "to" : "from"} ${label(other)} <span class="faint">- ${servicesText([p.forward, p.backward].filter(Boolean), 2)}</span></span>
            ${vs.length ? badge(`may violate ${controlsOf(vs).join(", ")}`, "bad") : ""}</button>`;
        })}</div>` : html`<p class="muted">No pass rule allows traffic from or to this zone (as far as the approximate evaluation sees).</p>`}</div>
      <div class="cv-insp-section"><h3>Assets (${assets.length})</h3>
        ${assets.length ? html`<div class="seg-assets">${assets.slice(0, ASSET_LIMIT).map((a) => html`<div class="seg-asset">
          <div style="min-width:0"><a href="#/assets/${enc(a.id)}">${a.name}</a> <span class="faint">${TYPE_LABEL[a.type] || a.type}</span>
            ${(a.badges || []).map((b) => badge(b, b === "external" ? "info" : b === "manual" ? "accent" : ""))}
            <div class="mono faint" style="font-size:11.5px;overflow-wrap:anywhere">${(a.addresses || []).slice(0, 4).join(", ")}</div>
            ${a.warning ? html`<div class="warn-text" style="font-size:12px">Placed by hand, but ${a.warning}</div>` : ""}</div>
          <div class="row" style="gap:4px;flex-wrap:nowrap">${a.vuln?.critical ? html`<span class="sev critical">${a.vuln.critical}</span>` : ""}${a.vuln?.high ? html`<span class="sev high">${a.vuln.high}</span>` : ""}
            ${operator ? html`<button type="button" class="btn sm" data-act="insp-place" data-id="${a.id}">Place...</button>` : ""}</div></div>`)}</div>
          ${assets.length > ASSET_LIMIT ? html`<p class="faint" style="font-size:12px">and ${assets.length - ASSET_LIMIT} more in the List view (L).</p>` : ""}`
          : html`<p class="muted">${z.id === INTERNET ? "No asset with a public address outside the firewall's networks." : "No asset has an address in this zone's networks."}</p>`}</div>`;
  }

  function ruleRows(rules) {
    return html`<div class="table-wrap"><table class="table compact seg-rules"><thead><tr><th>#</th><th>Rule</th><th>Log</th></tr></thead><tbody>
      ${rules.map((r) => {
        const changeId = ruleChange(r);
        return html`<tr><td class="mono">${r.order ?? "-"}</td><td style="min-width:0"><div class="mono nc-line">${r.action} ${r.source} -> ${r.destination} ${r.service}</div>
          <div class="faint" style="font-size:12px;overflow-wrap:anywhere">${r.description || "no description"}${(r.interfaces || []).length ? ` · on ${r.interfaces.join(", ")}` : r.floating ? " · floating" : ""}${r.hits != null ? ` · ${r.hits} hits` : ""}</div>
          ${changeId ? html`<div style="font-size:12px">${badge("added by Atrium", "accent")} <a href="#/integration/segmentation/change/${enc(changeId)}">${changeId}</a></div>` : ""}
          ${r.any_any ? badge("any to any", "bad") : ""}</td><td>${r.log ? icon("check") : "-"}</td></tr>`;
      })}</tbody></table></div>`;
  }

  function direction(e) {
    const x = e.exposure;
    return html`<div class="seg-dir"><h3>${label(e.source)} &rarr; ${label(e.target)}</h3>
      <div class="tag-list" style="margin-bottom:6px">${e.any_service ? badge("any service", "bad") : ""}${(e.services || []).map((s) => html`<span class="badge mono" title="${s.proto}/${s.ports || ""}">${s.label}</span>`)}</div>
      ${(e.violations || []).length ? html`<ul class="seg-viol">${e.violations.map((v) => html`<li>${badge(v.verdict, v.verdict === "forbidden" ? "bad" : "warn")}
        policy rule <span class="mono">${v.policy}</span>, control <a href="#/compliance/controls">${v.control || "-"}</a>${v.possible ? html` <span class="faint">(possible: the evaluation is approximate)</span>` : ""}</li>`)}</ul>` : ""}
      ${x && (x.critical || x.high || x.not_on_allowed_ports?.critical || x.not_on_allowed_ports?.high) ? html`<p style="font-size:12.5px">${x.critical || x.high ? html`<span class="warn-text">${exposureText(x)} on the allowed ports</span>` : "No critical or high finding on the allowed ports"}${x.not_on_allowed_ports?.critical || x.not_on_allowed_ports?.high ? html`<span class="faint">; ${(x.not_on_allowed_ports.critical || 0) + (x.not_on_allowed_ports.high || 0)} more not on allowed ports</span>` : ""}</p>` : ""}
      ${(e.notes || []).length ? html`<ul class="seg-viol faint">${e.notes.map((n) => html`<li>${n}</li>`)}</ul>` : ""}
      ${ruleRows(e.rules || [])}</div>`;
  }

  function pendingList(list) {
    return list.length ? html`<div class="cv-insp-section"><h3>Proposed changes</h3>${list.map((c0) => {
      const c = changeOf(c0.id) || c0;
      return html`<div class="seg-change"><div class="row" style="gap:6px">${statusBadge(c.status)}<b>${OP_LABEL[c.op] || c.op}</b><span class="faint">${c.id}${c.proposed_by ? ` by ${c.proposed_by}` : ""}</span></div>
        ${c.history ? html`<div style="margin:6px 0">${lifecycle(c, true)}</div>` : ""}
        <button type="button" class="btn sm" data-act="insp-change" data-id="${c.id}">Open change</button></div>`;
    })}</div>` : "";
  }

  function trafficPanel(e) {
    const parts = e.raw;
    const v = e.verdict;
    return html`${head(html`${label(e.from.id)} ${e.backward ? html`&harr;` : html`&rarr;`} ${label(e.to.id)}`, `Allowed traffic${e.backward ? " both ways" : ""} · ${fwName()}`)}
      <div class="row" style="gap:6px;margin-bottom:10px">${v === "forbidden" || v === "restricted" ? badge(`may violate ${controlsOf(e.violations).join(", ")}`, v === "forbidden" ? "bad" : "warn")
        : v === "unevaluable" ? badge("cannot evaluate: unclassified zone", "warn") : badge("within the policy", "ok")}
        ${e.any ? badge("any service", "bad") : ""}${e.exposure ? badge(exposureText(e.exposure), "warn") : ""}${badge(plural(e.rules, "rule"))}</div>
      <p class="faint" style="font-size:12px;margin-bottom:8px">"May allow": block rules, rule order and NAT are not evaluated, so some of this traffic may be blocked.</p>
      <div class="cv-insp-actions">
        ${writable() ? html`<button type="button" class="btn sm danger" data-act="insp-disable">${icon("x")}Disable rules...</button>` : ""}
        ${writable() && canAllow(item(e.from.id)?.zone) && canAllow(item(e.to.id)?.zone) ? html`<button type="button" class="btn sm" data-act="insp-allow-pair">${icon("plus")}Allow more...</button>` : ""}
        <button type="button" class="btn sm" data-act="insp-select" data-id="${e.from.id}">${label(e.from.id)}</button>
        <button type="button" class="btn sm" data-act="insp-select" data-id="${e.to.id}">${label(e.to.id)}</button>
        ${data.selected ? html`<a class="btn sm" href="#/network/${enc(data.selected)}/rules">${icon("network")}All rules</a>` : ""}</div>
      ${operator && !writable() ? html`<p class="faint" style="font-size:12px">Proposing changes: ${reasonText(fw()?.reason)}.</p>` : ""}
      ${pendingList(e.pending)}
      ${parts.map(direction)}`;
  }

  /** What a change does in this map's words: the services an allow opens, or how many rules it disables/enables. */
  function whatOf(c) {
    const allow = (c.ops || []).find((o) => o.op === "allow");
    if (allow) return `allow ${(allow.services || []).map((s) => (s.ports ? `${s.proto}/${s.ports}` : s.proto)).join(", ")}${allow.log === false ? "" : ", logged"}`;
    const count = (op) => (c.ops || []).filter((o) => o.op === op).reduce((n, o) => n + (o.rules?.length || 0), 0);
    const parts = [["disable_rules", "disable"], ["enable_rules", "enable"]].filter(([op]) => count(op)).map(([op, word]) => `${word} ${plural(count(op), "rule")}`);
    return parts.join(", ") || changeSummary(c);
  }

  function changePanel(e) {
    const c = changeOf(e.change.id) || e.change;
    const me = session.user?.username;
    const canWithdraw = WAITING.includes(c.status) && operator && (c.proposed_by === me || admin);
    return html`${head(`Change ${c.id}`, `${OP_LABEL[c.op] || c.op} · ${fwName()}`)}
      ${c.history ? html`<div style="margin-bottom:10px">${lifecycle(c)}</div>` : html`<div style="margin-bottom:8px">${statusBadge(c.status)}</div>`}
      ${c.emergency ? html`<div style="margin-bottom:8px">${badge("emergency", "bad")}</div>` : ""}
      ${c.status === "verifying" && c.rollback_until ? html`<p style="font-size:12.5px"><b>Confirming connectivity</b> (${countdown(c.rollback_until)})</p>` : ""}
      <dl class="kv">
        <dt>Traffic</dt><dd>${label(e.from.id)} &rarr; ${label(e.to.id)}</dd>
        ${c.ops ? html`<dt>What</dt><dd style="overflow-wrap:anywhere">${whatOf(c)}</dd>` : ""}
        <dt>Proposed by</dt><dd>${c.proposed_by || "-"}${c.proposed_by && c.proposed_by === me ? " (you)" : ""}${c.created_at ? html` <span class="faint">${timeAgo(c.created_at)}</span>` : ""}</dd>
        ${c.expires_at && WAITING.includes(c.status) ? html`<dt>Expires</dt><dd>${dateTime(c.expires_at)} (${countdown(c.expires_at)})</dd>` : ""}
        ${c.scheduled_for ? html`<dt>Scheduled</dt><dd>${dateTime(c.scheduled_for)}</dd>` : ""}
        ${c.rollback ? html`<dt>Rollback</dt><dd>${rollbackLabel(c.rollback)}</dd>` : ""}
        ${c.justification ? html`<dt>Why</dt><dd class="nc-just">${c.justification}</dd>` : ""}</dl>
      <p class="faint" style="font-size:12px;margin-top:10px">Firewall changes are approved on the Approvals page, by an administrator ${data.guardrails?.device_changes_need_second_person === false ? "" : "who did not propose them"}.</p>
      <div class="cv-insp-actions"><button type="button" class="btn sm primary" data-act="insp-change" data-id="${c.id}">${icon("file")}Open change</button>
        ${c.status === "proposed" ? html`<a class="btn sm" href="#/approvals">${icon("checkCircle")}Approvals</a>` : ""}
        ${canWithdraw ? html`<button type="button" class="btn sm danger" data-act="insp-withdraw" data-id="${c.id}">${icon("x")}Withdraw</button>` : ""}</div>`;
  }

  // inspector actions
  actions(canvas.inspector, {
    "insp-close": () => { canvas.select(null); canvas.focusMap(); },
    "insp-select": (d) => (model.items.has(d.id) ? canvas.select(d.id, { reveal: true }) : selectEdge(d.id)),
    "insp-allow": () => allowPanel(canvas.selection, null),
    "insp-allow-pair": () => { const e = model.edges.get(canvas.selection); if (e) allowPanel(e.from.id, e.to.id); },
    "insp-disable": () => disablePanel(canvas.selection),
    "insp-role": () => roleDialog(canvas.selection),
    "insp-place": (d) => placeDialog(d.id),
    "insp-move": (d) => moveBy(canvas.selection, d.dir),
    "insp-change": (d) => showChange(d.id),
    async "insp-withdraw"(d, btn) {
      if (!(await confirmDialog("Withdraw this change?", "It will not be applied; its approval is closed. A new proposal is needed to make it later.", "Withdraw"))) return;
      btn.disabled = true;
      try {
        await del(`/segmentation/changes/${enc(d.id)}`);
        toast("Change withdrawn", "ok");
        canvas.announce(`Change ${d.id} withdrawn`);
      } catch (err) {
        toast(err.message, "bad");
      }
      load();
    },
  });

  function showChange(id) {
    const opener = canvas.selection;
    openChange(id, { deviceName: fwName(), onClose: () => { if (opener && (model.items.has(opener) || model.edges.has(opener))) canvas.focus(opener); } })
      .catch((err) => toast(err.message, "bad"));
  }

  // ---------- changes ----------
  function refocus(id) {
    return () => { if (id && (model.items.has(id) || model.edges.has(id))) canvas.focus(id); };
  }

  function afterProposal(result) {
    load().then(() => {
      const id = `chg:${result.change.id}`;
      if (model.edges.has(id)) canvas.select(id, { reveal: true });
      else if (result.change.edge && model.index.get(result.change.edge)) selectEdge(model.index.get(result.change.edge));
      canvas.announce(`Change ${result.change.id} proposed, waiting for approval`);
    });
  }

  function allowPanel(from, to) {
    if (!writable()) return canvas.announce(operator ? `Changes cannot be proposed now: ${reasonText(fw()?.reason)}` : "Operators propose firewall changes");
    const opener = canvas.selection || from;
    openChangePanel({ firewall: data.selected, deviceName: fwName(), op: "allow", zones: data.zones, source: from, target: to,
      onDone: afterProposal, onClose: refocus(opener) });
  }

  function disablePanel(id) {
    const e = model.edges.get(id);
    if (!e || e.kind !== "traffic") return canvas.announce("Select allowed traffic to disable its rules");
    if (!writable()) return canvas.announce(operator ? `Changes cannot be proposed now: ${reasonText(fw()?.reason)}` : "Operators propose firewall changes");
    const rules = e.raw.flatMap((x) => x.rules || []).filter((r) => r.action === "pass" && r.enabled !== false);
    openChangePanel({ firewall: data.selected, deviceName: fwName(), op: "disable_rules", zones: data.zones, edge: e.forward.id, rules,
      edgeTitle: `${label(e.from.id)} ${e.backward ? "<->" : "->"} ${label(e.to.id)}`, onDone: afterProposal, onClose: refocus(id) });
  }

  function deleteKey(id) {
    const e = model.edges.get(id);
    if (!e) return canvas.announce(item(id) ? "Select allowed traffic to act on it; zones come from the firewall" : "Nothing is selected");
    if (e.kind === "change") return canvas.announce("A proposed change is withdrawn from its details: press Enter");
    disablePanel(id);
  }

  // ---------- zones and assets ----------
  function roleDialog(zid) {
    const it = item(zid);
    if (!it || !admin) return;
    const z = it.zone;
    modal({
      title: `Role of ${it.label}`, minRole: "admin", submit: "Save",
      body: html`<p class="muted" style="margin-bottom:12px">The role decides the zone's lane and colour and which segmentation-policy rules apply to its traffic, so it changes
          compliance verdicts (controls HB-NW-*). The device is not changed.</p>
        ${field("Role", html`<select name="role">${options([["", "Guess from the name"], ...ROLES.filter((r) => r !== "internet").map((r) => [r, ROLE_LABEL[r]])], z.role_source === "manual" ? z.role : "")}</select>`,
          z.role_source === "manual" ? "" : `Now guessed as ${ROLE_LABEL[z.role] || z.role}. Choosing a role confirms it.`)}
        ${field("Label", html`<input name="label" maxlength="80" value="${z.label || ""}" placeholder="${z.name || ""}">`, "Shown instead of the device's name; leave empty to use the device's name.")}`,
      onClose: refocus(zid),
      async onSubmit(f) {
        await patch(`/segmentation/zones/${enc(zid)}`, { role: String(f.get("role") || "") || null, label: String(f.get("label") || "").trim() || null });
        toast("Zone updated", "ok");
        canvas.announce(`${it.label}: role saved`);
        load();
      },
    });
  }

  function placeDialog(assetId) {
    const a = (data.assets || []).find((x) => x.id === assetId) || (data.unplaced || []).find((x) => x.id === assetId);
    if (!a || !operator) return;
    const opener = canvas.selection;
    const zones = orderedZones(data.zones || []);
    modal({
      title: `Place ${a.name}`, minRole: "operator", submit: "Save",
      body: html`<div class="notice" style="margin-bottom:12px">${icon("alert")}<div class="muted">This only changes where Atrium draws the asset. It does not change the network.</div></div>
        ${field("Zone", html`<select name="zone">${options([["", "Automatic (from its addresses)"], ...zones.map((z) => [z.id, `${zoneLabel(z)} (${ROLE_LABEL[z.role] || z.role})`])], a.placement === "manual" ? a.zone : "")}</select>`,
          (a.addresses || []).length ? `Addresses: ${a.addresses.slice(0, 4).join(", ")}` : a.reason || "")}`,
      onClose: refocus(opener),
      async onSubmit(f) {
        await put(`/segmentation/placements/${enc(assetId)}`, { zone_id: String(f.get("zone") || "") || null });
        toast(`${a.name} placed`, "ok");
        load();
      },
    });
  }

  function moveBy(id, dir) {
    const it = item(id);
    const sc = canvas.scene;
    if (!it || !sc) return;
    const entries = sc.order.get(it.lane) || [];
    const at = entries.findIndex((x) => x.id === id);
    const to = dir === "up" ? at - 1 : at + 1;
    if (at < 0 || to < 0 || to >= entries.length) return canvas.announce(`${it.label} is already ${dir === "up" ? "first" : "last"} in ${LANE_TITLE[it.lane]}`);
    const orders = planMove(entries.filter((x) => x.id !== id), id, to);
    store.move(Object.fromEntries(Object.entries(orders).map(([x, order]) => [x, { order }])));
    canvas.announce(`${it.label} moved to position ${to + 1} in ${LANE_TITLE[it.lane]}`);
  }

  // ---------- policy ----------
  async function openPolicy() {
    let p;
    try { p = await get("/segmentation/policy"); } catch (err) { return toast(err.message, "bad"); }
    const roles = (list) => (list || []).map((r) => ROLE_LABEL[r] || r).join(", ");
    const m = modal({
      title: "Segmentation policy", wide: true, submit: null, cancel: "Close",
      body: html`<p class="muted" style="margin-bottom:10px">Every allowed-traffic edge is checked against these rules by zone role. A match is a <em>possible</em> violation:
          the evaluation is approximate, so the HB-NW controls show it as partial, never as failed. Version ${p.version}${p.default ? " (the default policy)" : ""}${p.updated_by ? ` - changed by ${p.updated_by} ${timeAgo(p.updated_at)}` : ""}.</p>
        <div class="table-wrap"><table class="table compact"><thead><tr><th>Rule</th><th>From</th><th>To</th><th>Verdict</th><th>Control</th></tr></thead><tbody>
          ${p.rules.map((r) => html`<tr><td class="mono">${r.id}${r.description ? html`<div class="faint" style="font-family:inherit;font-size:12px">${r.description}</div>` : ""}</td>
            <td>${r.match ? "any source, any destination, any service" : roles(r.from)}</td><td>${r.match ? "" : roles(r.to)}${(r.except_services || []).length ? html`<div class="faint" style="font-size:12px">except ${r.except_services.map((s) => `${s.proto}/${s.ports || ""}`).join(", ")}</div>` : ""}</td>
            <td>${badge(r.verdict, r.verdict === "forbidden" ? "bad" : r.verdict === "restricted" ? "warn" : "ok")}</td><td>${r.control || "-"}</td></tr>`)}</tbody></table></div>
        ${admin ? html`<details style="margin-top:12px"><summary class="muted" style="cursor:pointer">Edit the policy (administrators)</summary>
          <p class="faint" style="font-size:12px;margin:8px 0">JSON list of rules: {id, from: [roles], to: [roles], verdict: allowed | restricted | forbidden, control, except_services?, description?}
            or {id, match: "any_source_any_destination_any_service", verdict, control}. Roles: ${p.roles.join(", ")}. An earlier "allowed" rule is an exception for the same pair.</p>
          <textarea name="policy" rows="14" class="mono" spellcheck="false" aria-label="Policy rules as JSON">${JSON.stringify(p.rules, null, 2)}</textarea>
          <div class="cv-result" data-part="pol-result" role="status"></div>
          <div class="row" style="gap:6px;margin-top:8px"><button type="button" class="btn sm primary" data-act="pol-save">Save policy</button>
            <button type="button" class="btn sm" data-act="pol-defaults">Restore the defaults</button></div></details>` : ""}`,
    });
    const say = (text, tone) => { const out = m.el.querySelector('[data-part="pol-result"]'); out.className = `cv-result ${tone}`; out.textContent = text; };
    const save = async (rules) => {
      try {
        const saved = await put("/segmentation/policy", { rules });
        say(`Saved (version ${saved.version}).`, "ok");
        m.el.querySelector("[name=policy]").value = JSON.stringify(saved.rules, null, 2);
        load();
      } catch (err) {
        say(err.message, "bad");
      }
    };
    actions(m.el, {
      "pol-save"() {
        let rules;
        try { rules = JSON.parse(m.el.querySelector("[name=policy]").value); } catch (err) { return say(`Not valid JSON: ${err.message}`, "bad"); }
        save(rules);
      },
      async "pol-defaults"() {
        if (await confirmDialog("Restore the default policy?", "The current rules are replaced by Atrium's default segmentation policy.", "Restore")) save(p.defaults);
      },
    });
  }

  // ---------- filters, find, menus ----------
  const matches = (id) => {
    if (!find) return true;
    const z = item(id)?.zone;
    return !!z && [zoneLabel(z), z.name, z.role, ROLE_LABEL[z.role], ...(z.subnets || [])].some((t) => String(t || "").toLowerCase().includes(find));
  };
  function applyFilter() {
    if (!find) return canvas.setFilter(null);
    canvas.setFilter((kind, id) => {
      if (kind === "item") return matches(id);
      const e = model.edges.get(id);
      return !!e && (matches(e.from.id) || matches(e.to.id));
    });
  }

  function closeMenu() {
    if (!menu) return false;
    const kind = menu.dataset.kind;
    menu.remove();
    menu = null;
    const b = canvas.shell.querySelector(`[data-act="seg-${kind}"]`);
    b?.setAttribute("aria-expanded", "false");
    b?.focus();
    return true;
  }

  function openMenu(kind) {
    if (menu) {
      const same = menu.dataset.kind === kind;
      closeMenu();
      if (same) return;
    }
    menu = document.createElement("div");
    menu.className = "cv-menu";
    menu.dataset.kind = kind;
    menu.setAttribute("role", "dialog");
    menu.setAttribute("aria-label", kind === "view" ? "Map view" : "Firewall changes");
    if (kind === "view") fillView(menu); else fillChanges(menu);
    canvas.shell.append(menu);
    canvas.shell.querySelector(`[data-act="seg-${kind}"]`).setAttribute("aria-expanded", "true");
    menu.querySelector("button, input, a")?.focus();
  }

  function fillView(el) {
    const seg = (key, list) => html`<div class="seg" role="group" aria-label="${key}">${list.map(([k, t]) => html`<button type="button" data-traffic="${k}" aria-pressed="${prefs.traffic === k}" class="${prefs.traffic === k ? "active" : ""}">${t}</button>`)}</div>`;
    setHTML(el, html`<h4>Allowed traffic</h4>
      ${seg("Which allowed traffic", [["auto", "Automatic"], ["focus", "Selection + issues"], ["all", "All"]])}
      <p class="faint" style="font-size:12px;margin-top:6px">${prefs.traffic === "auto" ? `Automatic shows everything up to 24 connections; above that the selected zone's traffic, possible violations and proposed changes. ` : ""}
        ${model.counts.edges > 60 ? "Many connections: the List view's zone-pair matrix may read better." : ""}</p>
      <h4>Overlays</h4>
      <div class="stack" style="gap:6px"><button type="button" class="btn sm seg-toggle" data-overlay="compliance" aria-pressed="${prefs.compliance}">${icon("shield")}Compliance: possible policy violations</button>
        <button type="button" class="btn sm seg-toggle" data-overlay="vulns" aria-pressed="${prefs.vulns}">${icon("bug")}Vulnerabilities: open findings</button></div>
      <h4>Legend</h4><div class="faint" style="font-size:12px;line-height:1.9">
        <div><span class="cv-legend"></span>may allow traffic (arrowhead: direction; two: both ways)</div>
        <div><span class="cv-legend bad"></span>may violate the segmentation policy (dashed halo)</div>
        <div><span class="cv-legend hatch"></span>any service (hatched)</div>
        <div><span class="cv-legend accent"></span>proposed change (clock)</div>
        <div><span class="cv-legend strike"></span>disable proposed</div>
        <div>Thicker lines carry more services. Zone colour and glyph show the role.</div></div>`);
  }

  function fillChanges(el) {
    const open = changes.filter((c) => OPEN.includes(c.status));
    const done = changes.filter((c) => !OPEN.includes(c.status)).slice(0, 8);
    const row = (c) => {
      const onMap = model.edges.has(`chg:${c.id}`) || (c.edge && model.index.get(c.edge) && OPEN.includes(c.status));
      return html`<div class="seg-crow"><div class="row" style="gap:6px">${statusBadge(c.status)}<b>${OP_LABEL[c.op] || c.op}</b><span class="faint">${c.id}</span></div>
        <div class="faint" style="font-size:12px;overflow-wrap:anywhere">${changeSummary(c)}${c.proposed_by ? ` · ${c.proposed_by}` : ""} · ${timeAgo(c.created_at)}</div>
        <div class="row" style="gap:6px;margin-top:4px">${onMap ? html`<button type="button" class="btn sm" data-chg-show="${c.id}">Show on map</button>` : ""}
          <button type="button" class="btn sm" data-chg-open="${c.id}">Open</button></div></div>`;
    };
    setHTML(el, html`<h4>Waiting or in progress (${open.length})</h4>
      ${open.length ? open.map(row) : html`<p class="faint" style="font-size:12px">None.${writable() ? " Drag from a zone's handle to another zone to propose one." : ""}</p>`}
      <h4>Recent</h4>${done.length ? done.map(row) : html`<p class="faint" style="font-size:12px">No finished changes yet.</p>`}
      ${data?.selected ? html`<p style="margin-top:8px"><a href="#/network/${enc(data.selected)}/changes">All changes of ${fwName()}</a></p>` : ""}`);
  }

  function menuClick(e) {
    const t = e.target.closest("[data-traffic], [data-overlay], [data-chg-show], [data-chg-open]");
    if (!t || !menu?.contains(t)) return;
    if (t.dataset.traffic) {
      prefs.traffic = t.dataset.traffic;
      writePref("filters", prefs);
      rebuild();
      fillView(menu);
      menu.querySelector(`[data-traffic="${prefs.traffic}"]`)?.focus();
    } else if (t.dataset.overlay) {
      prefs[t.dataset.overlay] = !prefs[t.dataset.overlay];
      writePref("filters", prefs);
      rebuild();
      fillView(menu);
      menu.querySelector(`[data-overlay="${t.dataset.overlay}"]`)?.focus();
      canvas.announce(`${t.dataset.overlay === "vulns" ? "Vulnerability" : "Compliance"} overlay ${prefs[t.dataset.overlay] ? "on" : "off"}`);
    } else if (t.dataset.chgShow) {
      const id = t.dataset.chgShow;
      closeMenu();
      followLink(["change", id]);
    } else if (t.dataset.chgOpen) {
      const id = t.dataset.chgOpen;
      closeMenu();
      showChange(id);
    }
  }
  canvas.shell.addEventListener("click", menuClick);
  const outside = (e) => { if (menu && !menu.contains(e.target) && !e.target.closest('[data-act="seg-view"], [data-act="seg-changes"]')) closeMenu(); };
  document.addEventListener("pointerdown", outside);

  const findInput = canvas.shell.querySelector('[data-part="seg-find"]');
  const clearFind = () => { findInput.value = ""; find = ""; applyFilter(); notices(); };
  findInput.addEventListener("input", debounce(() => { find = findInput.value.trim().toLowerCase(); applyFilter(); notices(); }, 150));
  findInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      const sc = canvas.scene;
      const first = sc && sc.lanes.flatMap((l) => (sc.order.get(l.id) || []).map((x) => x.id)).find(matches);
      if (first) canvas.select(first, { reveal: true }); else canvas.announce("No zones match");
    }
    if (e.key === "Escape" && findInput.value) { e.preventDefault(); e.stopPropagation(); clearFind(); }
  });
  canvas.shell.querySelector('[data-part="seg-fw"]').addEventListener("change", (e) => {
    firewall = e.target.value;
    writePref("firewall", firewall);
    canvas.select(null, { quiet: true });
    load().then(() => canvas.announce(`Showing ${fwName()}`));
  });

  async function refresh(btn) {
    if (btn) btn.disabled = true;
    try {
      const r = await post("/segmentation/refresh", data?.selected ? { firewall: data.selected } : {});
      const failed = (r.results || []).filter((x) => !x.ok);
      toast(failed.length ? `Reading failed: ${failed[0].error || failed[0].detail || "error"}` : (r.skipped || []).length && !(r.started || []).length
        ? `Not read: ${r.skipped[0].reason}` : "Firewall read", failed.length ? "bad" : "ok");
    } catch (err) {
      toast(err.message, "bad");
    } finally {
      if (btn) btn.disabled = false;
    }
    load();
  }

  actions(canvas.shell, {
    "seg-view": () => openMenu("view"),
    "seg-changes": () => openMenu("changes"),
    "seg-refresh": (_, btn) => refresh(btn),
    "seg-policy": () => openPolicy(),
    async "seg-reset"() {
      if (!(await confirmDialog("Reset arrangement", "Put every zone back in its default place? This changes the map for everyone.", "Reset"))) return;
      try { await store.reset(); toast("Arrangement reset", "ok"); } catch (err) { toast(err.message, "bad"); }
    },
    "seg-retry": () => load(),
    "seg-import": () => openImport(),
    "seg-clear-find": () => clearFind(),
    "seg-show-all": () => { prefs.traffic = "all"; writePref("filters", prefs); rebuild(); canvas.announce("Showing all allowed traffic"); },
    "note-change": (d) => showChange(d.id),
    "tray-place": (d) => placeDialog(d.id),
    async "dev-test"(d, btn) {
      btn.disabled = true;
      try {
        const r = await post(`/tools/${enc(d.id)}/connection/test`);
        toast(r.ok ? "Connection ok" : r.detail || "Test failed", r.ok ? "ok" : "bad");
      } catch (err) { toast(err.message, "bad"); } finally { btn.disabled = false; }
      load();
    },
    async "dev-refresh"(d, btn) {
      btn.disabled = true;
      try { await post(`/network/devices/${enc(d.id)}/refresh`); toast("Read started", "ok"); } catch (err) { toast(err.message, "bad"); } finally { btn.disabled = false; }
      load();
    },
  });

  // ---------- list view (the main screen-reader path) ----------
  function renderList(el) {
    if (!data) return setHTML(el, html`<div class="empty faint">Loading...</div>`);
    if (!data.firewalls.length) return setHTML(el, emptyView());
    if (!listWired) {
      listWired = true;
      actions(el, {
        "ls-select": (d) => { canvas.setList(false); setTimeout(() => (model.items.has(d.id) ? canvas.select(d.id, { reveal: true }) : selectEdge(d.id)), 30); },
        "ls-edge": (d) => { canvas.setList(false); setTimeout(() => selectEdge(model.index.get(d.id) || d.id), 30); },
        "ls-allow": (d) => allowPanel(d.id, null),
        "ls-disable": (d) => {
          const drawn = model.index.get(d.id);
          if (!model.edges.has(drawn)) { model = buildModel(data, { traffic: prefs.traffic, selection: drawn, overlays: prefs }); canvas.update(model, store.doc); }
          disablePanel(drawn);
        },
        "ls-role": (d) => roleDialog(d.id),
        "ls-place": (d) => placeDialog(d.id),
        "ls-change": (d) => showChange(d.id),
      });
    }
    const zones = orderedZones(data.zones || []);
    const raw = (data.edges || []).slice().sort((a, b) => b.violations.length - a.violations.length || label(a.source).localeCompare(label(b.source)) || label(a.target).localeCompare(label(b.target)));
    const mx = matrix(data.zones || [], data.edges || []);
    const pending = new Map();
    for (const c of data.changes || []) if (c.edge) pending.set(c.edge, [...(pending.get(c.edge) || []), c]);
    setHTML(el, html`
      <p class="muted" style="margin-bottom:8px">${fwName()}${fw()?.snapshot ? `, read ${timeAgo(fw().snapshot.read_at)}` : ""}. "May allow": the evaluation is approximate (see the note above).</p>
      <h3>Zones (${zones.length})</h3>
      <div class="table-wrap"><table class="table compact"><thead><tr><th>Zone</th><th>Role</th><th>Networks</th><th>Assets</th><th>Findings</th><th><span class="sr-only">Actions</span></th></tr></thead><tbody>
        ${zones.map((z) => html`<tr><td><b>${zoneLabel(z)}</b>${z.label && z.name && z.label !== z.name ? html` <span class="faint">(${z.name})</span>` : ""}</td>
          <td>${ROLE_LABEL[z.role] || z.role}${isUnconfirmed(z) && z.id !== INTERNET ? html` ${badge("not confirmed", "warn")}` : ""}</td>
          <td class="mono" style="font-size:12px;overflow-wrap:anywhere">${(z.subnets || []).join(", ") || "-"}</td><td>${z.asset_count ?? 0}</td>
          <td>${findingsText(z.vuln) ? sevBadges(z.vuln) : html`<span class="faint">-</span>`}</td>
          <td><div class="row" style="gap:6px;flex-wrap:nowrap;justify-content:flex-end"><button type="button" class="btn sm" data-act="ls-select" data-id="${z.id}">Select on map</button>
            ${admin && z.id !== INTERNET ? html`<button type="button" class="btn sm" data-act="ls-role" data-id="${z.id}">${isUnconfirmed(z) ? "Confirm role..." : "Role..."}</button>` : ""}
            ${writable() && canAllow(z) ? html`<button type="button" class="btn sm" data-act="ls-allow" data-id="${z.id}">Allow traffic to...</button>` : ""}</div></td></tr>`)}
      </tbody></table></div>
      <h3>Allowed traffic (${raw.length}) <span class="faint" style="font-weight:400;font-size:12px">may allow - approximate</span></h3>
      ${raw.length ? html`<div class="table-wrap"><table class="table compact"><thead><tr><th>From</th><th>To</th><th>Services</th><th>Rules</th><th>May violate</th><th>Exposure</th><th>Change</th><th><span class="sr-only">Actions</span></th></tr></thead><tbody>
        ${raw.map((e) => {
          const pend = pending.get(e.id) || [];
          return html`<tr><td>${label(e.source)}</td><td>${label(e.target)}</td><td>${e.any_service ? badge("any", "bad") : ""}${(e.services || []).map((s) => s.label).join(", ")}</td>
            <td>${e.rule_count}</td><td>${e.violations.length ? badge(controlsOf(e.violations).join(", "), e.violations.some((v) => v.verdict === "forbidden") ? "bad" : "warn") : html`<span class="faint">-</span>`}</td>
            <td>${exposureText(e.exposure) || html`<span class="faint">-</span>`}</td>
            <td>${pend.length ? pend.map((c) => html`<button type="button" class="btn sm" data-act="ls-change" data-id="${c.id}">${OP_LABEL[c.op] || c.op}: ${c.status}</button>`) : html`<span class="faint">-</span>`}</td>
            <td><div class="row" style="gap:6px;flex-wrap:nowrap;justify-content:flex-end"><button type="button" class="btn sm" data-act="ls-edge" data-id="${e.id}">Select on map</button>
              ${writable() ? html`<button type="button" class="btn sm" data-act="ls-disable" data-id="${e.id}">Disable rules...</button>` : ""}</div></td></tr>`;
        })}</tbody></table></div>` : html`<p class="muted">No pass rule allows traffic between zones.</p>`}
      <h3>Zone-pair matrix</h3>
      ${mx ? html`<div class="table-wrap"><table class="table compact seg-matrix"><caption class="sr-only">Allowed traffic from the zone in each row to the zone in each column</caption>
        <thead><tr><th scope="col">From \ To</th>${mx.zones.map((z) => html`<th scope="col">${zoneLabel(z)}</th>`)}</tr></thead><tbody>
        ${mx.zones.map((a) => html`<tr><th scope="row">${zoneLabel(a)}</th>${mx.zones.map((b) => {
          if (a.id === b.id) return html`<td class="faint" aria-label="same zone">·</td>`;
          const e = mx.cell(a.id, b.id);
          if (!e) return html`<td class="faint">-</td>`;
          const text = `${e.any_service ? "any" : `${e.services.length} service${e.services.length === 1 ? "" : "s"}`}${e.violations.length ? `, may violate ${controlsOf(e.violations).join(", ")}` : ""}`;
          return html`<td class="${e.violations.length ? "seg-cell-bad" : ""}"><button type="button" class="linkish" data-act="ls-edge" data-id="${e.id}"
            aria-label="${zoneLabel(a)} to ${zoneLabel(b)}: ${text}">${text}</button></td>`;
        })}</tr>`)}</tbody></table></div>` : html`<p class="muted">More than ${MATRIX_MAX} zones: use the allowed-traffic table above.</p>`}
      <h3>Unplaced assets (${(data.unplaced || []).length})</h3>
      ${(data.unplaced || []).length ? html`<div class="table-wrap"><table class="table compact"><thead><tr><th>Asset</th><th>Why</th><th><span class="sr-only">Actions</span></th></tr></thead><tbody>
        ${data.unplaced.map((a) => html`<tr><td><a href="#/assets/${enc(a.id)}">${a.name}</a></td><td class="muted">${a.reason}</td>
          <td>${operator ? html`<button type="button" class="btn sm" data-act="ls-place" data-id="${a.id}">Place...</button>` : ""}</td></tr>`)}</tbody></table></div>`
        : html`<p class="muted">Every asset with an address is drawn in a zone.</p>`}
      <h3>Changes</h3>
      ${changes.length ? html`<div class="table-wrap"><table class="table compact"><thead><tr><th>Change</th><th>Status</th><th>What</th><th>Proposed by</th><th>When</th></tr></thead><tbody>
        ${changes.map((c) => html`<tr><td><button type="button" class="linkish mono" data-act="ls-change" data-id="${c.id}">${c.id}</button></td><td>${statusBadge(c.status)}</td>
          <td style="overflow-wrap:anywhere">${OP_LABEL[c.op] || c.op}: ${changeSummary(c)}</td><td>${c.proposed_by || "-"}</td><td>${timeAgo(c.created_at)}</td></tr>`)}</tbody></table></div>`
        : html`<p class="muted">No firewall changes yet.</p>`}`);
  }

  return {
    dispose() {
      disposed = true;
      offs.forEach((off) => off());
      window.removeEventListener("atrium:events-reconnected", onReconnect);
      document.removeEventListener("visibilitychange", onVisible);
      document.removeEventListener("pointerdown", outside);
      clearInterval(timer);
      stopTicker();
      canvas.destroy();
    },
    select(kind, id) {
      if (!data) { pendingLink = [kind, id]; return; }
      followLink([kind, id]);
    },
  };
}
