// Integration strategies per tool (identity, events, data flows, generated connector, adapters and patches): how far
// each has got and the next step. Used by the Integration hub's overview and by the tool page.
import { post } from "./api.js";
import { canAskAgain, proposeText } from "./manifest-edit.js";
import { actions, badge, can, html, icon, toast } from "./ui.js";

export const STRATEGY_IDS = ["identity", "events", "data_flows", "generated_connector", "adapter"];
export const STRATEGY_TITLES = {
  identity: "Single sign-on", events: "Events", data_flows: "Data flows", generated_connector: "Generated connector",
  adapter: "Adapters & patches",
};
const STATES = {
  active: ["active", "ok"], pending: ["pending", "warn"], failing: ["failing", "bad"], needs_decision: ["needs a decision", "warn"],
  needs_input: ["needs input", "warn"], available: ["available", "info"], needs_model: ["needs an AI model", ""], needs_claude: ["needs an AI model", ""],
  unavailable: ["unavailable", ""], not_needed: ["not needed", ""],
};
const ACTIONS = {
  approve: ["Review", "checkCircle"], choose_provider: ["Choose provider", "link"], connect_sso: ["Connect", "link"],
  import_provider: ["Import a provider", "plus"], configure_connection: ["Set up", "plug"], test_connection: ["Test", "activity"],
  generate_connector: ["Generate", "bot"], propose_patches: ["Propose patches", "wrench"], edit_manifest: ["Edit", "wrench"],
};
const LINKS = { approve: () => "#/approvals", configure_connection: (id) => `#/tools/${id}/connection`, test_connection: (id) => `#/tools/${id}/connection` };
const OPERATOR = new Set(["choose_provider", "connect_sso", "import_provider", "generate_connector", "propose_patches", "test_connection"]);
const ADMIN = new Set(["edit_manifest"]); // the manifest editor: how the hub starts a tool runs on the hub machine

export const stateBadge = (state) => badge(...(STATES[state] || [state, ""]));

/** The next-step control of a strategy item: a link or a [data-act="strategy"] button. */
export function strategyAction(toolId, item) {
  const spec = ACTIONS[item.action];
  if (!spec) return "";
  const [label, iconName] = spec;
  const role = ADMIN.has(item.action) ? "admin" : OPERATOR.has(item.action) ? "operator" : "";
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

// A manifest editor asked for from a page without one (the Integration hub's overview): the tool page opens it.
let editRequest = null;

/** Whether the tool page should open the manifest editor of `toolId` now (asked for elsewhere); asks only once. */
export function takeEditRequest(toolId) {
  const yes = editRequest === toolId;
  if (yes) editRequest = null;
  return yes;
}

/**
 * The toast after a propose pass: "N proposed; M waiting for approval; not proposed: <title>: <reason>" (or "No new
 * patches needed"). When something was rejected or failed, an administrator also gets "Propose again" (POST
 * /tools/{id}/patches {again: true}) - shown longer, so the reasons can be read.
 */
export function proposeToast(toolId, result, refresh) {
  const message = proposeText(result);
  const tone = result?.skipped?.length && !result?.patches?.length ? "warn" : "ok";
  if (!(can("admin") && canAskAgain(result))) return toast(message, tone);
  let box = document.querySelector(".toasts");
  if (!box) { box = document.createElement("div"); box.className = "toasts"; document.body.append(box); }
  const el = document.createElement("div");
  el.className = `toast ${tone}`;
  el.setAttribute("role", "status");
  el.textContent = message;
  const again = Object.assign(document.createElement("button"), { type: "button", className: "btn sm", textContent: "Propose again" });
  again.style.cssText = "display:block;margin-top:8px";
  again.addEventListener("click", async () => {
    again.disabled = true;
    try {
      const r = await post(`/tools/${encodeURIComponent(toolId)}/patches`, { again: true });
      el.remove();
      proposeToast(toolId, r, refresh);
    } catch (err) {
      toast(err.message, "bad");
    } finally {
      again.disabled = false;
    }
    refresh?.();
  });
  el.append(again);
  box.append(el);
  setTimeout(() => el.remove(), 15000);
  return undefined;
}

/**
 * Wire [data-act="strategy"] buttons inside `root`. `handlers` may override an action (e.g. open the provider picker,
 * the import dialog or the manifest editor); `refresh` reloads the view afterwards. Without a handler, "edit_manifest"
 * opens the tool page, which opens its editor.
 */
export function wireStrategies(root, { refresh, handlers = {} }) {
  actions(root, {
    async strategy(d, btn) {
      if (handlers[d.action]) return handlers[d.action](d.tool);
      if (d.action === "edit_manifest") {
        editRequest = d.tool;
        location.hash = `#/tools/${encodeURIComponent(d.tool)}/integration`;
        return undefined;
      }
      btn.disabled = true;
      try {
        if (d.action === "generate_connector") {
          const r = await post(`/tools/${encodeURIComponent(d.tool)}/connection/generate`);
          toast(r.applied ? "Generated connector applied - an administrator enters the credentials" : "The AI model proposed a connector - see Approvals", "ok");
        } else if (d.action === "propose_patches") {
          proposeToast(d.tool, await post(`/tools/${encodeURIComponent(d.tool)}/patches`), refresh);
        }
      } catch (err) {
        toast(err.message, "bad");
      } finally {
        btn.disabled = false;
      }
      refresh?.();
      return undefined;
    },
  });
}
