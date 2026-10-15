// The configure dialog of a widget (round4-dashboard-spec.md 10.9): a form built generically from the widget type's
// field descriptors (GET /api/widgets/catalog `fields`), a title override and a live preview (GET /api/widgets/preview,
// debounced) drawn by the same renderer as the grid. The server validates the config on every save; the preview runs
// the same checks, so a problem shows up here, next to its field, before anything is saved.
import { get } from "../api.js";
import { debounce, html, icon, modal, raw, setHTML } from "../ui.js";
import { summary, widgetBody } from "./widgets.js";

const PAGES = [["#/", "Home"], ["#/tools", "Apps"], ["#/integration", "Integration hub"], ["#/agents", "Agents"],
  ["#/approvals", "Approvals"], ["#/operator", "Operator"], ["#/network", "Network"], ["#/assets", "Assets"], ["#/people", "People"],
  ["#/vulnerabilities", "Vulnerabilities"], ["#/compliance", "Compliance hub"], ["#/extensions", "Extensions"], ["#/settings", "Settings"]];
const OPS = [["eq", "is"], ["ne", "is not"], ["in", "is one of"]];
const MAX_FILTERS = 5;
const MAX_TOOLS = 20;

let teamList = null;
async function loadTeams() {
  if (!teamList) teamList = get("/agents/teams").then((r) => (r.teams || []).map((t) => [t.team, t.name || t.team])).catch(() => []);
  return teamList;
}

const opt = (value, label, selected) => html`<option value="${value}" ${selected ? raw("selected") : ""}>${label}</option>`;
const checked = (on) => (on ? raw("checked") : "");

/** The title a new widget gets when nobody types one (as the server makes it): the metric's label, a record widget's
 *  domain ("Vulnerabilities by severity"), else the type's title. */
export function defaultTitle(catalog, inst) {
  if (inst.default_title) return inst.default_title;
  if (inst.type === "metric") return catalog.metrics.find((m) => m.key === inst.config?.metric)?.label || "Metric";
  const domain = inst.config?.domain ? (catalog.domains || []).find((d) => d.key === inst.config.domain) : null;
  if (domain && inst.type === "domain_count") {
    const by = inst.config.group_by ? domain.fields?.[inst.config.group_by]?.label : null;
    return by ? `${domain.label} by ${by.toLowerCase()}` : domain.label;
  }
  if (domain && inst.type === "domain_list") return domain.label;
  if (domain && inst.type === "domain_timeline") return `${domain.label} over time`;
  return catalog.types.find((t) => t.key === inst.type)?.title || "Widget";
}

// ---------- the form ----------

function domainOf(catalog, config) {
  return catalog.domains.find((d) => d.key === config.domain) || null;
}

/** The tools that bring a domain's records (their connection reads it). */
export function sourceTools(catalog, domain) {
  return catalog.tools.filter((t) => !domain || (t.reads || []).includes(domain));
}

// What depends on the chosen domain: field choices and filters of another domain do not apply to the new one.
const DOMAIN_BOUND = new Set(["field", "filters"]);

/** The config after the domain changed: fields of the old domain cleared, a source that does not bring the new one reset. */
export function forDomain(fields, config, catalog) {
  const next = { ...config };
  for (const spec of fields) {
    if (!DOMAIN_BOUND.has(spec.kind) && !(spec.kind === "tool" && spec.depends_on)) continue;
    if (spec.kind === "filters") next[spec.name] = [];
    else if (spec.kind === "field" && spec.options === "group_by") { // a breakdown keeps grouping, by the new domain's first field
      next[spec.name] = catalog.domains.find((d) => d.key === next.domain)?.group_by?.[0] ?? null;
    } else if (spec.kind === "tool") {
      const id = String(next[spec.name] || "").replace(/^tool:/, "");
      if (String(next[spec.name] || "").startsWith("tool:") && !sourceTools(catalog, next.domain).some((t) => t.id === id)) next[spec.name] = "all";
    } else delete next[spec.name];
  }
  return next;
}

function fieldChoices(spec, catalog, config) {
  const domain = domainOf(catalog, config);
  const names = domain && typeof spec.options === "string" ? domain[spec.options] || [] : [];
  return names.map((n) => [n, domain.fields?.[n]?.label || n]);
}

function control(spec, config, catalog, teams) {
  const id = `cf-${spec.name}`;
  const value = config[spec.name];
  const name = `f:${spec.name}`;
  const hint = spec.hint ? html`<span class="hint">${spec.hint}</span>` : "";
  const err = html`<span class="dash-field-error" data-error="${spec.name}" hidden></span>`;
  const wrap = (inner, label = true) => html`<div class="field" data-field="${spec.name}">
    ${label ? html`<label for="${id}">${spec.label}</label>` : ""}${inner}${hint}${err}</div>`;
  const choices = spec.options === "metrics" ? catalog.metrics.map((m) => [m.key, m.label])
    : Array.isArray(spec.options) ? spec.options.map((o) => [o.value, o.label]) : [];
  switch (spec.kind) {
    case "select":
      return wrap(html`<select id="${id}" name="${name}">${choices.map(([v, l]) => opt(v, l, v === (value ?? choices[0]?.[0])))}</select>`);
    case "multiselect": {
      const cur = value === "all" ? choices.map(([v]) => v) : Array.isArray(value) ? value : [];
      return html`<fieldset class="field dash-checks" data-field="${spec.name}"><legend>${spec.label}</legend>
        <div class="check-grid">${choices.map(([v, l]) => html`<label class="check"><input type="checkbox" name="${name}" value="${v}" ${checked(cur.includes(v))}><span>${l}</span></label>`)}</div>${hint}${err}</fieldset>`;
    }
    case "text":
      return wrap(html`<input id="${id}" name="${name}" value="${value ?? ""}" maxlength="${spec.max || 120}" autocomplete="off">`);
    case "textarea":
      return wrap(html`<textarea id="${id}" name="${name}" rows="7" maxlength="${spec.max || 2000}">${value ?? ""}</textarea>`);
    case "number":
      return wrap(html`<input id="${id}" name="${name}" type="number" inputmode="numeric" value="${value ?? ""}" ${spec.min != null ? html`min="${spec.min}"` : ""} ${spec.max != null ? html`max="${spec.max}"` : ""}
        placeholder="${spec.min != null && spec.max != null ? `${spec.min} to ${spec.max}` : ""}">`);
    case "toggle":
      return html`<div class="field" data-field="${spec.name}"><label class="check"><input type="checkbox" name="${name}" ${checked(value === true)}><span>${spec.label}</span></label>${hint}${err}</div>`;
    case "tool": {
      if (spec.depends_on || spec.domain) { // where records come from: all, added by hand, or one tool that reads the domain
        const domain = spec.domain || config[spec.depends_on];
        const tools = sourceTools(catalog, domain);
        const fixed = Array.isArray(spec.options) ? spec.options.map((o) => [o.value, o.label]) : [["all", "All sources"], ["manual", "Added by hand"]];
        const current = value ?? fixed[0][0];
        const known = fixed.some(([v]) => v === current) || tools.some((t) => current === `tool:${t.id}`);
        return wrap(html`<select id="${id}" name="${name}">${fixed.map(([v, l]) => opt(v, l, current === v))}
          ${tools.map((t) => opt(`tool:${t.id}`, t.name, current === `tool:${t.id}`))}
          ${!known ? opt(current, String(current).replace(/^tool:/, ""), true) : ""}</select>`);
      }
      return wrap(catalog.tools.length ? html`<select id="${id}" name="${name}">${catalog.tools.map((t) => opt(t.id, t.name, t.id === (value ?? catalog.tools[0].id)))}</select>`
        : html`<p class="muted" id="${id}">No tools are imported yet.</p>`);
    }
    case "tools": {
      const all = value === undefined || value === "all";
      const picked = Array.isArray(value) ? value : [];
      const tools = spec.domain ? sourceTools(catalog, spec.domain) : catalog.tools;
      return html`<fieldset class="field dash-checks" data-field="${spec.name}"><legend>${spec.label}</legend>
        <label class="check"><input type="radio" name="${name}:mode" value="all" ${checked(all)}><span>${spec.domain === "network" ? "All devices" : "All tools"}</span></label>
        <label class="check"><input type="radio" name="${name}:mode" value="pick" ${checked(!all)} ${tools.length ? "" : raw("disabled")}><span>Only these (up to ${MAX_TOOLS})</span></label>
        <div class="check-grid dash-pick" ${all ? raw("hidden") : ""}>${tools.map((t) => html`<label class="check"><input type="checkbox" name="${name}" value="${t.id}" ${checked(picked.includes(t.id))}><span>${t.name}</span></label>`)}</div>
        ${hint}${err}</fieldset>`;
    }
    case "team":
      return wrap(html`<select id="${id}" name="${name}">${opt("all", "All teams", (value ?? "all") === "all")}
        ${teams.map(([v, l]) => opt(v, l, v === value))}${value && value !== "all" && !teams.some(([v]) => v === value) ? opt(value, value, true) : ""}</select>`);
    case "domain":
      return wrap(html`<select id="${id}" name="${name}" data-rerender>${catalog.domains.map((d) => opt(d.key, d.label, d.key === (value ?? catalog.domains[0]?.key)))}</select>`);
    case "field": {
      const list = fieldChoices(spec, catalog, config);
      if (spec.options === "columns") {
        const cur = Array.isArray(value) ? value : [];
        return html`<fieldset class="field dash-checks" data-field="${spec.name}"><legend>${spec.label}</legend>
          <div class="check-grid">${list.map(([v, l]) => html`<label class="check"><input type="checkbox" name="${name}" value="${v}" ${checked(cur.includes(v))}><span>${l}</span></label>`)}</div>
          <span class="hint">Up to ${spec.max || 4}</span>${err}</fieldset>`;
      }
      const optional = spec.options === "group_by";
      return wrap(html`<select id="${id}" name="${name}">${optional ? opt("", "None", !value) : ""}${list.map(([v, l]) => opt(v, l, v === (value ?? (optional ? "" : list[0]?.[0]))))}</select>`);
    }
    case "filters": {
      const domain = domainOf(catalog, config);
      const names = domain?.filters || [];
      const rows = Array.isArray(value) ? value : [];
      return html`<fieldset class="field" data-field="${spec.name}"><legend>${spec.label}</legend>
        <div class="dash-rows">${rows.map((f, i) => filterRow(domain, names, f, i))}</div>
        ${rows.length < (spec.max || MAX_FILTERS) && names.length ? html`<button type="button" class="btn sm" data-cf="add-filter">${icon("plus")}Add a filter</button>` : ""}
        ${!names.length ? html`<p class="faint dash-small">This data type has no fields to filter on.</p>` : ""}${err}</fieldset>`;
    }
    case "links": {
      const rows = Array.isArray(value?.items ?? value) ? (value?.items ?? value) : [];
      return html`<fieldset class="field" data-field="${spec.name}"><legend>${spec.label}</legend>
        <div class="dash-rows">${rows.map((l, i) => linkRow(catalog, l, i))}</div>
        ${rows.length < (spec.max || 12) ? html`<button type="button" class="btn sm" data-cf="add-link">${icon("plus")}Add a link</button>` : ""}${err}</fieldset>`;
    }
    default:
      return html`<div class="field"><label>${spec.label}</label><p class="faint dash-small">This setting cannot be changed here; it keeps its value.</p></div>`;
  }
}

function filterRow(domain, names, f, i) {
  const def = domain?.fields?.[f.field] || {};
  const values = def.values || null;
  const cur = Array.isArray(f.value) ? f.value : f.value === undefined || f.value === null ? [] : [String(f.value)];
  const valueControl = values
    ? html`<select name="flt-value-${i}" aria-label="Value" ${f.op === "in" ? raw("multiple size=3") : ""}>${values.map((v) => opt(v, v, cur.includes(String(v))))}</select>`
    : html`<input name="flt-value-${i}" aria-label="Value" value="${cur.join(", ")}" maxlength="120" placeholder="${f.op === "in" ? "a, b, c" : ""}">`;
  return html`<div class="dash-row-edit" data-row="${i}">
    <select name="flt-field-${i}" aria-label="Field" data-rerender>${names.map((n) => opt(n, domain.fields?.[n]?.label || n, n === f.field))}</select>
    <select name="flt-op-${i}" aria-label="Condition" data-rerender>${OPS.map(([v, l]) => opt(v, l, v === (f.op || "eq")))}</select>
    ${valueControl}
    <button type="button" class="icon-btn sm" data-cf="del-filter" data-i="${i}" aria-label="Remove this filter">${icon("x")}</button></div>`;
}

function linkRow(catalog, l, i) {
  const targets = [...PAGES.map(([v, label]) => [v, label]), ...catalog.tools.map((t) => [`tool:${t.id}`, `${t.name} (its own page)`])];
  const known = targets.some(([v]) => v === l.target);
  return html`<div class="dash-row-edit" data-row="${i}">
    <input name="lnk-label-${i}" aria-label="Link text" value="${l.label || ""}" maxlength="60" placeholder="Text">
    <select name="lnk-target-${i}" aria-label="Opens">${targets.map(([v, label]) => opt(v, label, v === l.target))}
      ${l.target && !known ? opt(l.target, l.target, true) : ""}</select>
    <button type="button" class="icon-btn sm" data-cf="del-link" data-i="${i}" aria-label="Remove this link">${icon("x")}</button></div>`;
}

/** The config the form holds now, from the fields the type declares. */
export function readConfig(form, fields, previous = {}) {
  const fd = new FormData(form);
  const config = {};
  for (const spec of fields) {
    const name = `f:${spec.name}`;
    switch (spec.kind) {
      case "select": case "domain": case "team":
        if (fd.has(name)) config[spec.name] = fd.get(name);
        break;
      case "tool":
        if (fd.has(name)) config[spec.name] = fd.get(name);
        break;
      case "multiselect":
        config[spec.name] = fd.getAll(name);
        break;
      case "text": {
        const v = String(fd.get(name) ?? "").trim();
        config[spec.name] = v || null;
        break;
      }
      case "textarea":
        config[spec.name] = String(fd.get(name) ?? "");
        break;
      case "number": {
        const v = String(fd.get(name) ?? "").trim();
        if (v !== "") config[spec.name] = Number(v);
        break;
      }
      case "toggle":
        config[spec.name] = fd.has(name);
        break;
      case "tools":
        config[spec.name] = fd.get(`${name}:mode`) === "pick" ? fd.getAll(name).slice(0, MAX_TOOLS) : "all";
        break;
      case "field":
        if (spec.options === "columns") config[spec.name] = fd.getAll(name).slice(0, spec.max || 4);
        else if (fd.has(name)) config[spec.name] = fd.get(name) || null;
        break;
      case "filters": {
        const rows = [];
        for (let i = 0; fd.has(`flt-field-${i}`); i++) {
          const op = fd.get(`flt-op-${i}`) || "eq";
          const given = fd.getAll(`flt-value-${i}`).map(String);
          const text = String(given[0] ?? "");
          const parts = (given.length > 1 ? given : op === "in" ? text.split(",") : [text]).map((s) => s.trim()).filter(Boolean);
          rows.push({ field: fd.get(`flt-field-${i}`), op, value: op === "in" ? parts : parts[0] ?? "" });
        }
        config[spec.name] = rows;
        break;
      }
      case "links": {
        const items = [];
        for (let i = 0; fd.has(`lnk-label-${i}`); i++) items.push({ label: String(fd.get(`lnk-label-${i}`)).trim(), target: fd.get(`lnk-target-${i}`) });
        config[spec.name] = items;
        break;
      }
      default:
        if (spec.name in previous) config[spec.name] = previous[spec.name];
    }
  }
  return config;
}

// ---------- the dialog ----------

/**
 * Opens the dialog for `inst` ({type, config, title, w, h, default_title?}); onSave({config, title}) runs when it is
 * saved with a config the server accepts. `isNew`: the widget is added by saving.
 */
export async function openConfigure({ catalog, inst, isNew = false, onSave }) {
  const type = catalog.types.find((t) => t.key === inst.type);
  if (!type) return;
  const teams = type.fields.some((f) => f.kind === "team") ? await loadTeams() : [];
  let config = structuredClone(inst.config || {});
  const domainField = type.fields.find((f) => f.kind === "domain");
  if (domainField && !config[domainField.name] && catalog.domains.length) { // a new record widget starts on the first domain
    config = forDomain(type.fields, { ...config, [domainField.name]: catalog.domains[0].key }, catalog);
  }
  let placeholder = defaultTitle(catalog, { ...inst, config });
  const h = Math.min(inst.h || type.size.default.h, 5);
  let seq = 0;

  const fieldsHTML = () => type.fields.length ? type.fields.map((f) => control(f, config, catalog, teams)) : html`<p class="muted">This widget has no settings.</p>`;
  const m = modal({
    title: isNew ? `Add: ${type.title}` : `Configure ${inst.title || placeholder}`,
    wide: true,
    submit: isNew ? "Add widget" : "Save",
    body: html`<div class="dash-config">
      <div class="dash-config-form">
        <p class="dash-form-error notice bad" data-error="_form" hidden></p>
        <div data-cf-fields>${fieldsHTML()}</div>
        <div class="field"><label for="cf-title">Title</label>
          <input id="cf-title" name="title" value="${inst.title || ""}" maxlength="80" placeholder="${placeholder}" autocomplete="off">
          <span class="hint" data-cf-title-hint>Leave empty for "${placeholder}".</span></div>
      </div>
      <div class="dash-config-preview"><h3 class="dash-sub">Preview</h3>
        <article class="widget preview t-${type.key}" style="--h:${h}" aria-label="Preview">
          <div class="widget-body" data-cf-preview>${widgetBody(undefined, inst)}</div></article>
        <p class="sr-only" aria-live="polite" data-cf-summary></p></div></div>`,
    onSubmit: async (_, form) => {
      config = readConfig(form, type.fields, config);
      const title = String(form.elements.title.value || "").trim() || null;
      const problem = await check(config);
      if (problem) { showError(problem); return true; }
      onSave({ config, title });
    },
  });
  const form = m.el;
  const fieldsEl = form.querySelector("[data-cf-fields]");
  const previewEl = form.querySelector("[data-cf-preview]");
  const summaryEl = form.querySelector("[data-cf-summary]");

  const url = (cfg, fresh) => `/widgets/preview?type=${encodeURIComponent(type.key)}&config=${encodeURIComponent(JSON.stringify(cfg))}${fresh ? "&fresh=1" : ""}`;
  async function check(cfg) {
    try {
      await get(url(cfg, false));
      return null;
    } catch (err) {
      return err.message || "These settings are not valid";
    }
  }

  function clearErrors() {
    form.querySelectorAll("[data-error]").forEach((el) => { el.hidden = true; el.textContent = ""; });
    form.querySelectorAll("[aria-invalid]").forEach((el) => el.removeAttribute("aria-invalid"));
  }
  function showError(message) {
    clearErrors();
    // "Tool overview: tool_id: Field required" -> next to the tool field, when a field is named
    const spec = type.fields.find((f) => new RegExp(`(^|[\\s:.])${f.name}([\\s:.]|$)`).test(message));
    const box = form.querySelector(`[data-error="${spec ? spec.name : "_form"}"]`) || form.querySelector('[data-error="_form"]');
    box.textContent = message;
    box.hidden = false;
    if (spec) {
      const input = form.querySelector(`[name="f:${spec.name}"], [name="f:${spec.name}:mode"]`);
      input?.setAttribute("aria-invalid", "true");
      input?.focus();
    }
  }

  const preview = debounce(async () => {
    const mine = ++seq;
    const cfg = readConfig(form, type.fields, config);
    if (domainField) { // a record widget's generated title follows its domain and grouping
      placeholder = defaultTitle(catalog, { type: inst.type, config: cfg });
      form.elements.title.placeholder = placeholder;
      form.querySelector("[data-cf-title-hint]").textContent = `Leave empty for "${placeholder}".`;
    }
    form.querySelector("[data-cf-preview]").setAttribute("aria-busy", "true");
    try {
      const result = await get(url(cfg, true));
      if (mine !== seq) return;
      clearErrors();
      setHTML(previewEl, widgetBody(result, { ...inst, config: cfg, title: String(form.elements.title.value || "").trim() || null }, { table: false }));
      summaryEl.textContent = summary(result, inst);
    } catch (err) {
      if (mine !== seq) return;
      setHTML(previewEl, html`<div class="dash-state">${icon("alert")}<p>${err.message}</p></div>`);
      summaryEl.textContent = `Preview: ${err.message}`;
    } finally {
      if (mine === seq) previewEl.removeAttribute("aria-busy");
    }
  }, 400);

  // fields that change the other fields' choices (the domain, a filter's field or condition) redraw the form
  const redraw = () => {
    config = readConfig(form, type.fields, config);
    const focusName = document.activeElement?.name;
    setHTML(fieldsEl, fieldsHTML());
    if (focusName) form.querySelector(`[name="${CSS.escape(focusName)}"]`)?.focus();
  };
  form.addEventListener("change", (e) => {
    if (domainField && e.target.name === `f:${domainField.name}`) {
      config = forDomain(type.fields, readConfig(form, type.fields, config), catalog);
      setHTML(fieldsEl, fieldsHTML());
      form.querySelector(`[name="f:${domainField.name}"]`)?.focus();
    } else if (e.target.matches?.("[data-rerender]")) redraw();
    if (e.target.matches?.('input[type="radio"][name$=":mode"]')) {
      const pick = e.target.closest("fieldset")?.querySelector(".dash-pick");
      if (pick) pick.hidden = e.target.value !== "pick";
    }
    preview();
  });
  form.addEventListener("input", (e) => { if (!e.target.matches?.("select")) preview(); });
  form.addEventListener("click", (e) => {
    const b = e.target.closest("[data-cf]");
    if (!b) return;
    config = readConfig(form, type.fields, config);
    const filters = type.fields.find((f) => f.kind === "filters");
    const links = type.fields.find((f) => f.kind === "links");
    if (b.dataset.cf === "add-filter" && filters) {
      const domain = domainOf(catalog, config);
      config[filters.name] = [...(config[filters.name] || []), { field: domain?.filters?.[0], op: "eq", value: "" }];
    } else if (b.dataset.cf === "del-filter" && filters) {
      config[filters.name] = config[filters.name].filter((_, i) => i !== +b.dataset.i);
    } else if (b.dataset.cf === "add-link" && links) {
      config[links.name] = [...(config[links.name] || []), { label: "", target: "#/" }];
    } else if (b.dataset.cf === "del-link" && links) {
      config[links.name] = config[links.name].filter((_, i) => i !== +b.dataset.i);
    } else return;
    setHTML(fieldsEl, fieldsHTML());
    const rows = fieldsEl.querySelectorAll(".dash-row-edit");
    (b.dataset.cf.startsWith("add") ? rows[rows.length - 1]?.querySelector("input, select") : fieldsEl.querySelector("[data-cf], input, select"))?.focus();
    preview();
  });
  preview();
  return m;
}
