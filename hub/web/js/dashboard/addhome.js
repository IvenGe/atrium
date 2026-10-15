// "Add to Home" (round4-dashboard-spec.md 10.16, stage D4): a button on Settings cards that pins the matching widget
// to the person's own dashboard - their home when it is personal, else their first personal dashboard, else a new
// "My dashboard" (a copy of the default, which then becomes their home). The widget goes to the first free place at
// its type's default size, through the normal PUT (version and validation); a widget with the same type and settings
// already there is not added twice. The planning is pure (node tests); addToHome does the requests.
import { get, post, put } from "../api.js";
import { html, icon, toast } from "../ui.js";
import { COLS, MAX_ROWS, firstFit, newWidgetId } from "./grid.js";

/** What each Settings card adds. */
export const HOME_WIDGETS = {
  safety_settings: { type: "safety_settings", config: {}, label: "the safety settings" },
  ai_models: { type: "ai_models", config: { show: "all" }, label: "the AI models" },
  llm_spend_today: { type: "metric", config: { metric: "llm_spend_today" }, label: "the AI spending" },
  network_overview: { type: "network_overview", config: { tools: "all" }, label: "the network devices" },
};
export const MY_DASHBOARD = "My dashboard";

/** JSON with sorted keys, so two configs compare by content. */
export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`;
  return JSON.stringify(value ?? null);
}

/** Whether a stored widget is the one a spec adds (same type and settings). */
export const sameWidget = (w, spec) => w.type === spec.type && canonical(w.config || {}) === canonical(spec.config || {});

/** Where the widget goes, from GET /api/dashboards: {id} of a personal dashboard, or {create: true, from, home} for a
 *  new "My dashboard" copied from the default (`home`: it becomes the person's home). */
export function homeTarget(list) {
  const dashes = list?.dashboards || [];
  const home = dashes.find((d) => d.id === list?.home_id);
  if (home?.scope === "personal") return { id: home.id };
  const mine = dashes.find((d) => d.scope === "personal");
  if (mine) return { id: mine.id };
  const from = list?.default_id || home?.id || null;
  return { create: true, from, home: true };
}

/** A new widget at the first free place of `widgets`, or null when there is no room (40 widgets, or no free cells). */
export function placeWidget(widgets, spec, size, limit = 40) {
  if (widgets.length >= limit) return null;
  const w = Math.min(Math.max(size?.w ?? 4, 1), COLS);
  const h = Math.max(size?.h ?? 3, 1);
  const spot = firstFit(widgets, w, h, COLS, MAX_ROWS);
  if (!spot) return null;
  return { id: newWidgetId(widgets.map((x) => x.id)), type: spec.type, x: spot.x, y: spot.y, w, h, title: null, config: spec.config };
}

const strip = ({ id, type, x, y, w, h, title, config }) => ({ id, type, x, y, w, h, title: title ?? null, config: config || {} });

/** The "Add to Home" button of a card header (every role: everyone has their own dashboards). */
export const homeButton = (key) => html`<button type="button" class="btn sm" data-act="home-add" data-home="${key}"
  aria-label="Add ${HOME_WIDGETS[key]?.label || "this"} to your Home dashboard">${icon("plus")}Add to Home</button>`;

/** Adds the widget of HOME_WIDGETS[key]; resolves {status: "added" | "exists", dashboard}. Throws the API's error. */
export async function addToHome(key) {
  const spec = HOME_WIDGETS[key];
  if (!spec) throw new Error("Nothing to add");
  const [list, catalog] = await Promise.all([get("/dashboards"), get("/widgets/catalog")]);
  const type = catalog.types.find((t) => t.key === spec.type);
  if (!type) throw new Error("This widget is not available to your role");
  let target = homeTarget(list);
  if (target.create) {
    const made = await post("/dashboards/mine", { title: MY_DASHBOARD, icon: "home", ...(target.from ? { from: target.from } : {}) });
    if (target.home) {
      const prefs = list.prefs || {};
      await put("/dashboards/prefs", { order: prefs.order || [], hidden: prefs.hidden || [], home: made.id, base_version: prefs.version ?? 0 })
        .catch(() => null); // the copy exists either way; it is just not the home yet
    }
    target = { id: made.id };
  }
  for (let attempt = 0; ; attempt++) {
    const d = await get(`/dashboards/${encodeURIComponent(target.id)}`);
    if (d.widgets.some((w) => sameWidget(w, spec))) return { status: "exists", dashboard: d };
    const widgets = d.widgets.map(strip);
    const added = placeWidget(widgets, spec, type.size?.default, list.limits?.widgets ?? 40);
    if (!added) throw new Error(`${d.title} has no room for another widget`);
    try {
      const saved = await put(`/dashboards/mine/${encodeURIComponent(d.id)}`, {
        title: d.title, icon: d.icon, description: d.description || "", widgets: [...widgets, added], base_version: d.version });
      return { status: "added", dashboard: saved };
    } catch (err) {
      if (err.status !== 409 || attempt) throw err; // changed in another tab meanwhile: once more with the new version
    }
  }
}

/** Runs addToHome for a button and says how it went. */
export async function onHomeAdd(btn) {
  const key = btn.dataset.home;
  btn.disabled = true;
  try {
    const { status, dashboard } = await addToHome(key);
    const link = { href: `#/d/${encodeURIComponent(dashboard.id)}`, text: "Open" };
    if (status === "exists") toast(`Already on ${dashboard.title}.`, "info", link);
    else toast(`Added to ${dashboard.title}.`, "ok", link);
  } catch (err) {
    if (err.status !== 401) toast(err.message, "bad");
  } finally {
    btn.disabled = false;
  }
}

/** Keeps an "Add to Home" button in a card's header slot ([data-slot="home"]) while the card redraws itself. */
export function keepHomeButton(card, key) {
  const fill = () => {
    const slot = card.querySelector('[data-slot="home"]');
    if (slot && !slot.querySelector('[data-act="home-add"]')) slot.insertAdjacentHTML("beforeend", String(homeButton(key)));
  };
  fill();
  const observer = new MutationObserver(fill);
  observer.observe(card, { childList: true, subtree: true });
  return () => observer.disconnect();
}
