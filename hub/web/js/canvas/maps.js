/** Integration map and segmentation map. Device and tool text is set with textContent or the html`` escaper. */

import { get, patch, post } from "../api.js";
import { can, emptyState, html, setHTML, toast } from "../ui.js";
import { createCanvas } from "./engine.js";

const NS = "http://www.w3.org/2000/svg";
const DOMAIN_APP = {
  assets: "app:assets", vulnerabilities: "app:vulnerabilities", controls: "app:compliance",
  risks: "app:compliance", frameworks: "app:compliance", assessments: "app:compliance",
  people: "app:people", accounts: "app:people", network: "app:network",
};

const INTEGRATION_LANES = [
  { id: "left", title: "Sources", x: 0, width: 280 },
  { id: "spine", title: "Hub apps", x: 340, width: 240 },
  { id: "right", title: "Destinations", x: 640, width: 280 },
  { id: "shelf", title: "Not connected", x: 980, width: 260 },
];

const SEGMENT_LANES = [
  { id: "internet", title: "Internet", x: 0, width: 220 },
  { id: "untrusted", title: "Untrusted", x: 260, width: 240 },
  { id: "users", title: "Users", x: 540, width: 240 },
  { id: "servers", title: "Servers", x: 820, width: 240 },
  { id: "management", title: "Management", x: 1100, width: 240 },
  { id: "other", title: "Other", x: 1380, width: 240 },
];

const ROLE_LANE = {
  internet: "internet", guest: "untrusted", iot: "untrusted", users: "users",
  dmz: "servers", servers: "servers", management: "management",
};

function svgEl(name, attrs) {
  const node = document.createElementNS(NS, name);
  for (const [key, value] of Object.entries(attrs || {})) node.setAttribute(key, String(value));
  return node;
}

function card(item, g, ctx) {
  const fill = document.createElementNS(NS, "rect");
  fill.setAttribute("width", ctx.w);
  fill.setAttribute("height", ctx.h);
  fill.setAttribute("rx", "10");
  fill.setAttribute("class", ctx.selected ? "node-card is-selected" : "node-card");
  if (item.color) fill.setAttribute("stroke", item.color);
  g.append(fill);
  const label = svgEl("text", { x: 12, y: 28, class: "node-label" });
  label.textContent = item.label || item.id;
  g.append(label);
  if (item.sub && ctx.k >= 0.5) {
    const sub = svgEl("text", { x: 12, y: 48, class: "node-sub" });
    sub.textContent = item.sub;
    g.append(sub);
  }
}

function hubEnd(end, domain) {
  if (!end || end === "hub") return DOMAIN_APP[domain] || "app:assets";
  if (end.startsWith("tool:") || end.startsWith("app:")) return end;
  return `tool:${end}`;
}

function integrationModel(payload) {
  const items = new Map();
  const edges = new Map();
  for (const app of payload.apps || []) {
    items.set(app.id, { id: app.id, label: app.label, sub: "Hub app", color: app.color, lane: "spine", kind: "app", href: app.href, order: items.size });
  }
  for (const node of payload.nodes || []) {
    const lane = node.lane_default === "right" ? "right" : node.lane_default === "shelf" || node.lane_default === "idp" ? (node.lane_default === "idp" ? "left" : "shelf") : "left";
    const tested = node.connection?.tested;
    items.set(node.id, {
      id: node.id, label: node.label, kind: "tool", ref: node.ref, href: `#/tools/${node.ref}`,
      lane, order: items.size, color: node.ui?.color || null,
      sub: [node.kind, node.status, tested ? (tested.ok ? "connection ok" : "connection failed") : "no connection"].filter(Boolean).join(" · "),
    });
  }
  const saved = payload.layout?.items || {};
  for (const [id, spec] of Object.entries(saved)) {
    const item = items.get(id);
    if (!item) continue;
    if (spec.lane && INTEGRATION_LANES.some((lane) => lane.id === spec.lane)) item.lane = spec.lane;
    if (Number.isFinite(spec.order)) item.order = spec.order;
  }
  for (const flow of payload.flows || []) {
    const source = hubEnd(flow.source, flow.domain);
    const target = hubEnd(flow.target, flow.domain);
    if (!items.has(source) || !items.has(target) || source === target) continue;
    const failing = flow.status === "enabled" && flow.last_result && flow.last_result.ok === false;
    edges.set(flow.id, {
      id: flow.id, source, target, kind: "flow", status: flow.status, failing, title: flow.title || flow.domain,
      primary: true,
    });
  }
  for (const link of payload.sso || []) {
    edges.set(link.id, { id: link.id, source: link.source, target: link.target, kind: "sso", status: link.state, title: "Single sign-on", primary: false });
  }
  for (const link of payload.capability_links || []) {
    const id = link.id || `cap:${link.source}:${link.target}:${link.capability || ""}`;
    edges.set(id, { id, source: link.source, target: link.target, kind: "capability", title: link.capability || "capability", primary: false });
  }
  for (const link of payload.events || []) {
    if (!items.has(link.source) || !items.has(link.target)) continue;
    edges.set(link.id, { id: link.id, source: link.source, target: link.target, kind: "event", title: link.event || "event", primary: false });
  }
  return { items, edges };
}

function segmentLane(zone) {
  return zone.lane && SEGMENT_LANES.some((lane) => lane.id === zone.lane) ? zone.lane : (ROLE_LANE[zone.role] || "other");
}

function segmentationModel(payload) {
  const items = new Map();
  const edges = new Map();
  (payload.zones || []).forEach((zone, index) => {
    const vuln = zone.vuln || {};
    const bits = [zone.role || "unknown"];
    if (zone.role_source === "heuristic") bits.push("role not confirmed");
    if (zone.asset_count) bits.push(`${zone.asset_count} assets`);
    if (vuln.critical || vuln.high) bits.push(`${vuln.critical || 0} critical, ${vuln.high || 0} high`);
    items.set(zone.id, {
      id: zone.id, label: zone.label || zone.name || zone.id, sub: bits.join(" · "),
      lane: segmentLane(zone), order: index, kind: "zone", role: zone.role, zone,
    });
  });
  for (const edge of payload.edges || []) {
    if (!items.has(edge.source) || !items.has(edge.target)) continue;
    const violations = edge.violations || [];
    edges.set(edge.id, {
      id: edge.id, source: edge.source, target: edge.target, kind: "rule", primary: true,
      title: violations.length ? `${violations.length} policy note${violations.length > 1 ? "s" : ""}` : "allowed",
      violations, pending: edge.pending_changes || [],
    });
  }
  return { items, edges };
}

function edgeStyle(edge) {
  if (edge.failing) return { cls: "edge-bad", dash: "6 4", chip: "failing", primary: true };
  if (edge.kind === "flow" && edge.status === "proposed") return { cls: "edge-warn", dash: "6 4", chip: "proposed", primary: true };
  if (edge.kind === "flow" && edge.status === "disabled") return { cls: "edge-faint", dash: "4 4", primary: true };
  if (edge.kind === "sso") return { cls: "edge-ok", chip: edge.status === "pending" ? "sso pending" : null, primary: false };
  if (edge.violations?.length) return { cls: "edge-bad", chip: "policy", primary: true };
  if (edge.pending?.length) return { cls: "edge-warn", dash: "5 4", chip: "change", primary: true };
  if (edge.kind === "capability") return { cls: "edge-cap", primary: false };
  return { cls: "edge-flow", primary: true };
}

function inspectorHtml(view, model, id, extra = "") {
  if (!id) return html`<p class="muted">Select an item on the map. Arrow keys move the selection. L opens the list.</p>${extra}`;
  const item = model.items.get(id);
  const edge = model.edges.get(id);
  if (item) {
    return html`<h3>${item.label}</h3><p class="muted">${item.sub || ""}</p>
      ${item.href ? html`<p><a href="${item.href}">Open</a></p>` : ""}
      ${item.zone?.subnets?.length ? html`<p class="faint">${item.zone.subnets.join(", ")}</p>` : ""}
      ${extra}`;
  }
  if (edge) {
    const from = model.items.get(edge.source);
    const to = model.items.get(edge.target);
    return html`<h3>${edge.title || edge.kind}</h3>
      <p>${from?.label || edge.source} → ${to?.label || edge.target}</p>
      ${edge.violations?.length ? html`<ul>${edge.violations.map((v) => html`<li>${v.policy}: ${v.verdict}</li>`)}</ul>` : ""}
      ${extra}`;
  }
  return html`<p class="muted">Nothing selected.</p>`;
}

function changeForm(payload) {
  const zones = payload.zones || [];
  const opts = zones.filter((z) => z.native_id).map((z) => html`<option value="${z.id}">${z.label || z.name || z.id}</option>`);
  return html`<form class="stack" data-change>
    <h3>Propose a change</h3>
    <p class="muted">Device changes stay off until an administrator turns the guardrail on. A different administrator approves.</p>
    <label>Source <select name="source_zone">${opts}</select></label>
    <label>Destination <select name="target_zone">${opts}</select></label>
    <label>Protocol <select name="proto"><option value="tcp">tcp</option><option value="udp">udp</option></select></label>
    <label>Ports <input name="ports" value="443" inputmode="numeric"></label>
    <label>Justification <textarea name="justification" rows="3" minlength="20" placeholder="At least 20 characters"></textarea></label>
    <div class="row">
      <button type="button" class="btn sm" data-act="preview" data-min-role="operator">Preview</button>
      <button type="submit" class="btn sm primary" data-min-role="operator">Propose</button>
    </div>
    <div data-preview></div>
  </form>`;
}

export async function mountMap(container, view, ctx) {
  const host = document.createElement("div");
  container.replaceChildren(host);
  let payload = null;
  let model = { items: new Map(), edges: new Map() };
  let canvas = null;
  let off = null;
  const move = can("operator");

  const showInspector = (id) => {
    if (!canvas) return;
    const extra = view === "segmentation" && payload ? changeForm(payload) : "";
    setHTML(canvas.inspector, inspectorHtml(view, model, id, extra));
    canvas.inspector.hidden = false;
    wireChange();
  };

  const saveMove = async (id, spec) => {
    const item = model.items.get(id);
    const slot = { order: spec.order };
    if (view === "integration" && item?.kind === "tool" && spec.lane && spec.lane !== "spine") slot.lane = spec.lane;
    const body = { items: { [id]: slot } };
    try {
      const layout = await patch(`/layouts/${view}`, body);
      canvas.applyLayout(layout.items);
      toast("Layout saved", "ok");
    } catch (err) {
      toast(err.message, "bad");
    }
  };

  canvas = createCanvas(host, {
    view,
    label: view === "segmentation" ? "Segmentation map" : "Integration map",
    roledescription: view === "segmentation" ? "segmentation map" : "integration map",
    lanes: view === "segmentation" ? SEGMENT_LANES : INTEGRATION_LANES,
    permissions: { move, connect: false },
    adapter: {
      size: () => ({ w: 220, h: 72 }),
      lane: (item) => item.lane,
      draw: card,
      edgeStyle,
      name: (id) => model.items.get(id)?.label || model.edges.get(id)?.title || id,
      canMove: (item) => ({ lanes: item?.kind === "app" ? ["spine"] : (view === "segmentation" ? SEGMENT_LANES : INTEGRATION_LANES).map((l) => l.id).filter((id) => id !== "spine") }),
      onMove: saveMove,
      onSelect: showInspector,
      onOpen: (id) => {
        const href = model.items.get(id)?.href;
        if (href) location.hash = href;
      },
    },
  });

  function wireChange() {
    const form = canvas.inspector.querySelector("[data-change]");
    if (!form || form.dataset.wired) return;
    form.dataset.wired = "1";
    const bodyOf = () => ({
      firewall: payload.selected,
      op: "allow",
      source_zone: form.source_zone.value,
      target_zone: form.target_zone.value,
      services: [{ proto: form.proto.value, ports: form.ports.value }],
      justification: form.justification.value,
      description: "map",
    });
    form.querySelector("[data-act=preview]").addEventListener("click", async () => {
      const slot = form.querySelector("[data-preview]");
      try {
        const preview = await post("/segmentation/changes/preview", bodyOf());
        const notes = preview.violations || preview.policy || [];
        setHTML(slot, html`<p class="notice">${preview.summary || "Preview ready."} ${Array.isArray(notes) && notes.length ? html`${notes.length} policy note(s).` : ""}</p>`);
      } catch (err) {
        setHTML(slot, html`<p class="notice bad">${err.message}</p>`);
      }
    });
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      try {
        const result = await post("/segmentation/changes", bodyOf());
        toast("Change proposed", "ok");
        if (result.approval_id) location.hash = "#/approvals";
      } catch (err) {
        toast(err.message, "bad");
      }
    });
  }

  async function load() {
    if (view === "segmentation") {
      const firewall = new URLSearchParams(location.hash.split("?")[1] || "").get("firewall");
      try {
        payload = await get(`/segmentation${firewall ? `?firewall=${encodeURIComponent(firewall)}` : ""}`);
      } catch (err) {
        setHTML(host, emptyState("radar", "Segmentation map unavailable", err.message));
        return;
      }
      model = segmentationModel(payload);
      if (!payload.zones?.length) {
        setHTML(host, emptyState("radar", "No firewall snapshot yet", "Connect a firewall and refresh its snapshot. The map shows zones from that read."));
        return;
      }
    } else {
      payload = await get("/integration/map");
      model = integrationModel(payload);
    }
    canvas.update(model, payload.layout || { items: {} });
    const stale = payload.firewalls?.find((f) => f.tool_id === payload.selected)?.snapshot?.stale;
    if (stale) canvas.announce("The firewall snapshot is stale. Refresh it before proposing a change.");
    showInspector(canvas.selection);
  }

  ctx?.live?.(["flow", "flow_removed", "tool", "tool_removed", "connection", "canvas_layout", "segmentation", "firewall_change"], () => {
    load().catch(() => canvas?.setPaused(true));
  }, 800);
  await load();
  return { destroy() { off?.(); canvas?.destroy(); } };
}
