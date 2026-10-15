// Integration strategies per tool (identity, events, data flows, generated connector, adapters and patches): how far
// each has got and the next step. Used by the Integration hub's overview and by the tool page.
import { post } from "./api.js";
import { actions, badge, html, icon, toast } from "./ui.js";

export const STRATEGY_IDS = ["identity", "events", "data_flows", "generated_connector", "adapter"];
export const STRATEGY_TITLES = {
  identity: "Single sign-on", events: "Events", data_flows: "Data flows", generated_connector: "Generated connector",
  adapter: "Adapters & patches",
};
const STATES = {
  active: ["active", "ok"], pending: ["pending", "warn"], failing: ["failing", "bad"], needs_decision: ["needs a decision", "warn"],
  available: ["available", "info"], needs_model: ["needs an AI model", ""], needs_claude: ["needs an AI model", ""], unavailable: ["unavailable", ""], not_needed: ["not needed", ""],
};
const ACTIONS = {
  approve: ["Review", "checkCircle"], choose_provider: ["Choose provider", "link"], connect_sso: ["Connect", "link"],
  import_provider: ["Import a provider", "plus"], configure_connection: ["Set up", "plug"], test_connection: ["Test", "activity"],
  generate_connector: ["Generate", "bot"], propose_patches: ["Propose patches", "wrench"],
};
const LINKS = { approve: () => "#/approvals", configure_connection: (id) => `#/tools/${id}/connection`, test_connection: (id) => `#/tools/${id}/connection` };
const OPERATOR = new Set(["choose_provider", "connect_sso", "import_provider", "generate_connector", "propose_patches", "test_connection"]);

export const stateBadge = (state) => badge(...(STATES[state] || [state, ""]));

/** The next-step control of a strategy item: a link or a [data-act="strategy"] button. */
export function strategyAction(toolId, item) {
  const spec = ACTIONS[item.action];
  if (!spec) return "";
  const [label, iconName] = spec;
  const role = OPERATOR.has(item.action) ? "operator" : "";
  if (LINKS[item.action]) {
    return html`<a class="btn sm" href="${LINKS[item.action](toolId)}" ${role ? html`data-min-role="${role}"` : ""}>${icon(iconName)}${label}</a>`;
  }
  return html`<button class="btn sm" data-act="strategy" data-action="${item.action}" data-tool="${toolId}" ${role ? html`data-min-role="${role}"` : ""}>${icon(iconName)}${label}</button>`;
}

/** Cards of one tool's strategies (tool page). */
export function strategyCards(toolId, items) {
  return html`<div class="strategy-grid">${items.map((s) => html`<div class="strategy ${s.state}">
    <div class="row" style="justify-content:space-between;gap:6px"><b>${STRATEGY_TITLES[s.id] || s.title}</b>${stateBadge(s.state)}</div>
    ${s.detail ? html`<p class="muted">${s.detail}</p>` : ""}
    ${s.action ? html`<div>${strategyAction(toolId, s)}</div>` : ""}</div>`)}</div>`;
}

/**
 * Wire [data-act="strategy"] buttons inside `root`. `handlers` may override an action (e.g. open the provider picker
 * or the import dialog); `refresh` reloads the view afterwards.
 */
export function wireStrategies(root, { refresh, handlers = {} }) {
  actions(root, {
    async strategy(d, btn) {
      if (handlers[d.action]) return handlers[d.action](d.tool);
      btn.disabled = true;
      try {
        if (d.action === "generate_connector") {
          const r = await post(`/tools/${encodeURIComponent(d.tool)}/connection/generate`);
          toast(r.applied ? "Generated connector applied - an administrator enters the credentials" : "The AI model proposed a connector - see Approvals", "ok");
        } else if (d.action === "propose_patches") {
          const r = await post(`/tools/${encodeURIComponent(d.tool)}/patches`);
          toast(r.patches?.length ? `${r.patches.length} patch(es) proposed - see Approvals` : "No new patches needed", "ok");
        }
      } catch (err) {
        toast(err.message, "bad");
      } finally {
        btn.disabled = false;
      }
      refresh?.();
    },
  });
}
