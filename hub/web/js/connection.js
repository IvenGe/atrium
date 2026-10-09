// A tool's connection to its own API, shown in the tool page's Connection tab: connector kind, settings (secrets are
// never shown, only whether they are set), connection test with its checks, choices loaded from the tool,
// capabilities, a connector generated with Claude, and this tool's data flows.
import { del, get, post, put } from "./api.js";
import { domainInfo, flowsTable, planFlows, wireFlows } from "./flows.js";
import { actions, badge, can, confirmDialog, dateTime, field, html, icon, options, setHTML, timeAgo, toast } from "./ui.js";

const BUILTIN_SCORE = 50; // as in integration/strategies.py: a detected built-in connector this sure needs no generated one
let catalogRequest = null;

/** The connector catalog (GET /api/connectors), loaded once per page load. */
export function loadCatalog() {
  catalogRequest ||= get("/connectors").catch((err) => { catalogRequest = null; throw err; });
  return catalogRequest;
}

function capabilityList(domains, actionsList = [], systemOfRecord = []) {
  const entries = Object.entries(domains || {}).filter(([, ops]) => ops?.length);
  if (!entries.length && !actionsList.length) return html`<p class="faint">None.</p>`;
  return html`<div class="cap-list">${entries.map(([domain, ops]) => html`<div class="cap">
      ${icon(domainInfo(domain).icon)}<span>${domainInfo(domain).label}</span>
      <span class="row" style="gap:4px;margin-left:auto">${ops.map((op) => badge(op, op === "write" ? "accent" : "info"))}
        ${systemOfRecord.includes(domain) ? badge("system of record", "ok") : ""}</span></div>`)}
    ${actionsList.filter((a) => a !== "scan_status").map((a) => html`<div class="cap">${icon(a === "scan" ? "radar" : "play")}<span>Action: ${a}</span></div>`)}</div>`;
}

function checksList(test) {
  return html`${(test.checks || []).map((c) => html`<div class="check-row">
    <div class="ico ${c.ok ? "pass" : "fail"}">${icon(c.ok ? "check" : "x")}</div>
    <div style="min-width:0"><b>${c.name}</b>${c.detail ? html`<div class="muted" style="overflow-wrap:anywhere;white-space:pre-line">${c.detail}</div>` : ""}</div></div>`)}`;
}

/**
 * Builds the panel for one tool; returns {el, refresh}. The element is kept across the tool page's redraws, so
 * settings typed but not saved survive live updates.
 */
export function mountConnection({ toolId, toolName }) {
  const root = document.createElement("div");
  root.className = "conn";
  setHTML(root, html`<div class="empty faint">Loading...</div>`);
  const path = `/tools/${encodeURIComponent(toolId)}/connection`;
  let view = null;
  let catalog = [];
  let kind = null; // chosen in the form
  let dirty = false;
  let testing = false;
  let generating = false;
  const loaded = {}; // field -> options loaded from the tool

  const entry = (k) => catalog.find((c) => c.kind === k);
  const fieldsOf = (k) => entry(k)?.fields || [];
  const sameKind = () => view?.kind && view.kind === kind;
  const builtin = () => (view?.detected || []).find((d) => d.kind !== "generic_rest" && d.score >= BUILTIN_SCORE);
  const part = (name) => root.querySelector(`[data-part="${name}"]`);

  function control(f) {
    const value = sameKind() ? view.config[f.name] : undefined;
    const current = value ?? f.default;
    const text = current === undefined || current === null ? "" : typeof current === "object" ? JSON.stringify(current, null, 2) : String(current);
    if (f.kind === "secret") {
      const set = sameKind() && view.secrets[f.name];
      return field(html`${f.label}${f.required ? " *" : ""} ${set ? badge("stored", "ok") : ""}`,
        html`<input type="password" data-field="${f.name}" autocomplete="new-password" spellcheck="false"
          placeholder="${set ? "Stored - leave empty to keep it" : f.placeholder || "Not set"}">`, f.help);
    }
    if (f.kind === "bool") {
      return html`<div class="field"><label class="check" style="color:var(--text);font-weight:500"><input type="checkbox" data-field="${f.name}"
        ${current === true || current === "true" ? "checked" : ""}> ${f.label}</label>${f.help ? html`<span class="hint">${f.help}</span>` : ""}</div>`;
    }
    if (f.kind === "json") {
      return field(html`${f.label}${f.required ? " *" : ""}`, html`<textarea data-field="${f.name}" rows="12" class="mono" spellcheck="false"
        style="font-size:12px" placeholder="{ }">${text}</textarea>`, f.help);
    }
    if (f.kind === "select" && f.options) {
      const choices = loaded[f.name];
      const list = choices ? [...choices.map((c) => [c.value, c.label])] : [];
      if (text && !list.some(([v]) => v === text)) list.unshift([text, choices ? `${text} (current, not offered by the tool)` : text]);
      return field(html`${f.label}${f.required ? " *" : ""}`, html`<div class="secret">
        <select data-field="${f.name}"><option value="">${f.default != null ? `Default (${f.default})` : "Not set"}</option>${options(list, text)}</select>
        <button type="button" class="btn" data-act="conn-options" data-for="${f.name}" title="Load the choices from ${toolName}">${icon("refresh")}<span class="txt">Load</span></button></div>`,
      f.help || "Choices come from the tool: save the connection, then Load.");
    }
    if (f.kind === "select") {
      const choices = (f.choices || []).map((c) => [c.value, c.label]);
      return field(html`${f.label}${f.required ? " *" : ""}`, html`<select data-field="${f.name}">
        ${f.default == null && !f.required ? html`<option value="">Not set</option>` : ""}${options(choices, text)}</select>`, f.help);
    }
    return field(html`${f.label}${f.required ? " *" : ""}`, html`<input type="${f.kind === "number" ? "number" : f.kind === "url" ? "url" : "text"}"
      ${f.kind === "number" ? html`step="any"` : ""} data-field="${f.name}" value="${text}" placeholder="${f.placeholder || ""}" spellcheck="false" autocomplete="off">`, f.help);
  }

  function renderForm() {
    const admin = can("admin");
    const detected = new Map((view.detected || []).map((d) => [d.kind, d.score]));
    const kinds = [...catalog].sort((a, b) => (detected.get(b.kind) || 0) - (detected.get(a.kind) || 0));
    const chosen = entry(kind);
    const fields = fieldsOf(kind);
    setHTML(part("form"), html`<form class="conn-form" novalidate autocomplete="off">
      <header class="row" style="justify-content:space-between;margin-bottom:10px"><h3>Settings</h3>
        ${view.updated_at ? html`<span class="faint" style="font-size:12px" title="${dateTime(view.updated_at)}">saved ${timeAgo(view.updated_at)}${view.updated_by ? ` by ${view.updated_by}` : ""}</span>` : ""}</header>
      ${admin ? "" : html`<div class="notice" style="margin-bottom:12px">${icon("lock")}<div class="muted">Only administrators change connection settings and credentials.
        ${can("operator") ? "You can test the connection and run its data flows." : ""}</div></div>`}
      <fieldset class="plain" ${admin ? "" : "disabled"}>
        ${field("Connector", html`<select name="kind">${options(kinds.map((c) => [c.kind,
          `${c.title}${detected.has(c.kind) ? ` - detected (${detected.get(c.kind)}%)` : ""}${c.error ? " - unavailable" : ""}`]), kind)}</select>`,
          chosen?.error ? html`<span style="color:var(--bad)">${chosen.error}</span>` : chosen?.description)}
        ${view.kind && view.kind !== kind ? html`<div class="notice warn" style="margin-bottom:12px">${icon("alert")}<div class="muted">Saving replaces the
          ${entry(view.kind)?.title || view.kind} connection; its stored credentials are not carried over.</div></div>` : ""}
        ${fields.some((f) => f.kind === "secret") && sameKind() ? html`<p class="faint" style="font-size:12px;margin:-4px 0 12px">Stored credentials are only sent to
          the address they were entered for: change the address and they must be entered again.</p>` : ""}
        <div class="conn-fields">${fields.map(control)}</div>
      </fieldset>
      <div class="row" data-min-role="admin" style="margin-top:4px">
        <button type="submit" class="btn primary" ${chosen && !chosen.error ? "" : "disabled"}>${icon("check")}Save and test</button>
        <button type="button" class="btn" data-act="conn-reset" ${dirty ? "" : html`style="display:none"`}>Discard changes</button>
        <span class="spacer"></span>
        ${view.kind ? html`<button type="button" class="btn danger" data-act="conn-remove">${icon("trash")}Remove connection</button>` : ""}
      </div></form>`);
  }

  function renderStatus() {
    const test = view.last_test;
    const title = view.kind ? entry(view.kind)?.title || view.kind : null;
    const declared = entry(kind);
    setHTML(part("status"), html`
      <header class="row" style="justify-content:space-between;margin-bottom:10px"><h3>Connection</h3>
        <button class="btn sm" data-act="conn-test" data-min-role="operator" ${view.kind && !testing ? "" : "disabled"}>${icon(testing ? "refresh" : "activity")}${testing ? "Testing..." : "Test connection"}</button></header>
      ${view.error ? html`<div class="notice bad" style="margin-bottom:10px">${icon("alert")}<div>${view.error}</div></div>` : ""}
      ${title ? html`<div class="row" style="gap:8px;margin-bottom:8px"><b>${title}</b>
          ${test ? (test.ok ? badge("working", "ok") : badge("test failed", "bad")) : badge("not tested", "warn")}
          ${view.generated ? badge("generated from the OpenAPI spec", "info") : ""}</div>
        ${test ? html`<p class="faint" style="font-size:12px;margin-bottom:6px" title="${dateTime(test.at)}">Tested ${timeAgo(test.at)}${test.detail ? html`: <span class="muted">${test.detail}</span>` : ""}</p>
          <div style="margin-bottom:12px">${checksList(test)}</div>` : html`<p class="muted" style="margin-bottom:12px">Test the connection: a successful test lets the Hub Supervisor propose data flows.</p>`}`
      : html`<p class="muted" style="margin-bottom:12px">Not connected. ${(view.detected || []).length
          ? html`Detected: ${view.detected.map((d) => html`<span class="badge">${d.title} ${d.score}%</span> `)}` : "No built-in connector recognised this tool."}</p>`}
      <h3 style="margin:4px 0 8px">Capabilities ${view.kind ? (test?.ok ? html`<span class="faint" style="font-weight:500;font-size:12px">reported by the last test</span>`
        : html`<span class="faint" style="font-weight:500;font-size:12px">declared by the connector</span>`) : html`<span class="faint" style="font-weight:500;font-size:12px">of ${declared?.title || "the chosen connector"}</span>`}</h3>
      ${view.kind ? capabilityList(view.capabilities, view.actions, view.system_of_record)
        : capabilityList(declared?.capabilities, declared?.actions, declared?.system_of_record)}`);
  }

  function renderGenerate() {
    const box = part("generate");
    const fits = builtin();
    if (view.generated || (fits && !view.can_generate) || (view.kind && view.kind !== "generic_rest")) { setHTML(box, ""); return; }
    let body;
    if (view.can_generate) {
      body = html`<p class="muted" style="margin-bottom:10px">No built-in connector fits ${toolName}. Claude can read its OpenAPI spec and write a
          Generic REST mapping; it is proposed as an approval, and an administrator then enters the credentials.</p>
        <button class="btn" data-act="conn-generate" data-min-role="operator" ${generating ? "disabled" : ""}>${icon("bot")}${generating ? "Generating..." : "Generate connector with Claude"}</button>`;
    } else if (view.has_openapi) {
      body = html`<p class="muted">Claude could generate a connector from ${toolName}'s OpenAPI spec. Start the hub with <code>ANTHROPIC_API_KEY</code> set to use it,
        or write a Generic REST mapping by hand.</p>`;
    } else {
      body = html`<p class="muted">No built-in connector fits and no OpenAPI spec is known. Choose <b>Generic REST API</b> and describe the API with a mapping,
        or re-import the tool with its OpenAPI spec URL to let Claude generate one.</p>`;
    }
    setHTML(box, html`<div class="sub-card"><h3 style="margin-bottom:8px">${icon("bot")} Generated connector</h3>${body}</div>`);
  }

  function renderFlows() {
    setHTML(part("flows"), html`<header class="row" style="justify-content:space-between;margin:18px 0 10px"><h3>Data flows of ${toolName}</h3>
        ${view.kind ? html`<button class="btn sm" data-act="conn-plan" data-min-role="operator">${icon("flow")}Plan data flows</button>` : ""}</header>
      ${flowsTable(view.flows || [], { showTool: false, empty: view.kind ? "No data flows yet. They are proposed after a successful connection test." : "Connect the tool to exchange data with the hub's apps." })}`);
  }

  function renderAll() {
    if (!root.querySelector("[data-part]")) {
      setHTML(root, html`<div class="grid split"><div data-part="form"></div>
        <div class="stack" style="gap:14px"><div data-part="status"></div><div data-part="generate"></div></div></div><div data-part="flows"></div>`);
    }
    renderForm();
    renderStatus();
    renderGenerate();
    renderFlows();
  }

  async function refresh() {
    if (view && !root.isConnected) return;
    [view, catalog] = await Promise.all([get(path), loadCatalog()]);
    if (!dirty || !kind) {
      kind = view.kind || view.detected?.[0]?.kind || (entry("generic_rest") ? "generic_rest" : catalog[0]?.kind);
      dirty = false;
    }
    if (!root.querySelector("[data-part]") || !dirty) renderAll();
    else { renderStatus(); renderGenerate(); renderFlows(); }
  }

  function readForm() {
    const config = {};
    const secrets = {};
    for (const f of fieldsOf(kind)) {
      const input = part("form").querySelector(`[data-field="${CSS.escape(f.name)}"]`);
      if (!input) continue;
      if (f.kind === "secret") { if (input.value) secrets[f.name] = input.value; continue; }
      if (f.kind === "bool") { config[f.name] = input.checked; continue; }
      const value = f.kind === "json" ? input.value : input.value.trim();
      if (!value.trim()) continue; // empty: the connector's default applies
      config[f.name] = f.kind === "number" ? Number(value) : value;
    }
    return { config, secrets };
  }

  async function test() {
    testing = true;
    renderStatus();
    try {
      const r = await post(`${path}/test`);
      view = r.connection;
      toast(r.ok ? `${toolName}: connection works${(view.flows || []).some((f) => f.status === "proposed") ? " - data flows proposed" : ""}` : `Test failed: ${r.detail}`, r.ok ? "ok" : "bad");
    } catch (err) {
      toast(err.message, "bad");
    } finally {
      testing = false;
    }
    if (!root.isConnected) return;
    renderStatus();
    renderFlows();
  }

  root.addEventListener("input", (e) => {
    if (!e.target.closest("[data-part=form]")) return;
    dirty = true;
    const reset = part("form").querySelector('[data-act="conn-reset"]');
    if (reset) reset.style.display = "";
  });
  root.addEventListener("change", (e) => {
    if (e.target.matches("select[name=kind]")) {
      kind = e.target.value;
      dirty = kind !== view.kind;
      renderForm();
      renderStatus();
      renderGenerate();
    }
  });
  root.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!can("admin")) return;
    const btn = e.target.querySelector("button[type=submit]");
    btn.disabled = true;
    try {
      view = await put(path, { kind, ...readForm() });
      dirty = false;
      toast(`Connection of ${toolName} saved`, "ok");
      renderAll();
    } catch (err) {
      btn.disabled = false;
      toast(err.message, "bad");
      return;
    }
    await test();
  });

  actions(root, {
    "conn-test": () => (dirty ? toast("Save the changes first - the test uses the saved settings", "warn") : test()),
    "conn-reset": () => { dirty = false; kind = view.kind || kind; renderForm(); renderStatus(); renderGenerate(); },
    async "conn-options"(d, btn) {
      if (!sameKind()) return toast("Save the connection first - the choices are read with its saved settings", "warn");
      btn.disabled = true;
      const name = d.for;
      try {
        const r = await get(`${path}/options/${encodeURIComponent(name)}`);
        const select = part("form").querySelector(`select[data-field="${CSS.escape(name)}"]`);
        const keep = select?.value;
        loaded[name] = r.options;
        const f = fieldsOf(kind).find((x) => x.name === name);
        if (select && f) {
          select.closest(".field").replaceWith(document.createRange().createContextualFragment(String(control(f))));
          const fresh = part("form").querySelector(`select[data-field="${CSS.escape(name)}"]`);
          if (fresh && keep !== undefined) fresh.value = r.options.some((o) => o.value === keep) || keep === "" ? keep : fresh.value;
        }
        toast(r.options.length ? `${r.options.length} choice${r.options.length > 1 ? "s" : ""} loaded` : "The tool offers no choices", r.options.length ? "ok" : "warn");
      } catch (err) {
        toast(err.message, "bad");
      } finally {
        btn.disabled = false;
      }
    },
    async "conn-remove"() {
      if (!(await confirmDialog("Remove connection", `Remove the connection of ${toolName}? Its stored credentials, data flows and sync links are deleted; records already in the hub stay.`, "Remove"))) return;
      try {
        await del(path);
        toast("Connection removed", "ok");
        dirty = false;
        kind = null;
        await refresh();
      } catch (err) {
        toast(err.message, "bad");
      }
    },
    async "conn-generate"() {
      generating = true;
      renderGenerate();
      try {
        const r = await post(`${path}/generate`);
        toast(r.applied ? "Generated connector applied - an administrator enters the credentials" : "Claude proposed a connector - see Approvals", "ok");
      } catch (err) {
        toast(err.message, "bad");
      } finally {
        generating = false;
      }
      if (root.isConnected) refresh().catch(() => {});
    },
    "conn-plan": () => planFlows(() => refresh().catch(() => {})),
  });
  wireFlows(root, { find: (id) => (view?.flows || []).find((f) => f.id === id), refresh: () => refresh().catch(() => {}), names: () => ({ [toolId]: toolName }) });

  refresh().catch((err) => setHTML(root, html`<div class="notice bad">${icon("alert")}<div>${err.message}</div></div>`));
  return { el: root, refresh: () => refresh().catch(() => {}) };
}
