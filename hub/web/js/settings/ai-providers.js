// Settings > AI providers: one card per provider (Claude, OpenAI, Azure OpenAI resources, model servers with an
// OpenAI-compatible API) with its status, key source, default model, models and what each supports; administrators
// add, edit, test and remove providers and check a model's tools and JSON support. Keys are write-only: a viewer never
// gets a key field, and the API never returns a key.
import { del, get, patch, post } from "../api.js";
import { capsChips, capsUnknown, hostLocation, keyLine, KIND_LABELS, parseModels, plainHttp, providerKind, providerStatus } from "../llm.js";
import { actions, badge, can, confirmDialog, html, icon, modal, options, setHTML, timeAgo, toast } from "../ui.js";

const SERVERS = "Ollama: http://localhost:11434/v1 - LM Studio: http://localhost:1234/v1 - vLLM: http://<host>:8000/v1 - llama.cpp server: http://<host>:8080/v1";
const SUBSCRIPTION = "A ChatGPT subscription (Plus, Pro, Business) does not include API access. API usage is billed separately: create an API key and add billing on platform.openai.com.";
const CLAUDE_MODELS = ["claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5", "claude-fable-5-1"];
const STRUCTURED = [["auto", "Automatic (JSON schema, JSON mode, instructions)"], ["json_schema", "JSON schema (response_format)"],
  ["json_object", "JSON mode (response_format json_object)"], ["prompt", "Instructions only"]];
const ADD = [
  ["local", "Local model server", "Ollama, LM Studio, vLLM or llama.cpp's server on your own hardware (OpenAI-compatible API)."],
  ["azure", "Azure OpenAI", "An Azure OpenAI resource: its v1 address, an API key and your deployment names."],
  ["cloud", "Other OpenAI-compatible cloud", "A hosted service with an OpenAI-compatible API (https). Counts as a cloud provider."],
];
let uid = 0;

/** A form field whose label names its control (for, id). */
function lfield(label, control, hint, id) {
  const hintId = hint ? `${id}-hint` : "";
  return html`<div class="field"><label for="${id}">${label}</label>${control}${hint ? html`<span class="hint" id="${hintId}">${hint}</span>` : ""}</div>`;
}

function modelRow(p, model, admin) {
  const caps = p.caps?.[model] ?? p.capabilities?.[model];
  const chips = capsChips(caps);
  const isDefault = model === p.default_model;
  return html`<li class="model-row"><span class="mono">${model}</span>${isDefault ? badge("default", "info") : ""}
    ${chips.map(([text, tone]) => badge(text, tone))}${caps?.source && caps.source !== "default" ? html`<span class="faint" style="font-size:11.5px">(${caps.source})</span>` : ""}
    ${admin && p.kind !== "anthropic" ? html`<button type="button" class="btn sm" data-act="prov-probe" data-id="${p.id}" data-model="${model}"
      aria-label="Check tools and JSON support of ${model}">${icon("activity")}Check tools and JSON</button>` : ""}</li>`;
}

const day = (ts) => new Date(ts * 1000).toISOString().slice(0, 10);
const REVIEW_DAYS = 365;

/** A cloud provider is a supplier (compliance control HB-SC-1): who owns the relationship and when its terms were
 * last reviewed. */
function supplierLine(p) {
  const s = p.supplier || {};
  const old = s.reviewed_at && Date.now() / 1000 - s.reviewed_at > REVIEW_DAYS * 86400;
  if (s.owner && s.reviewed_at && !old) {
    return html`<div class="faint" style="font-size:12px">Supplier owner: ${s.owner} - terms reviewed ${day(s.reviewed_at)}</div>`;
  }
  const what = !s.owner ? "No supplier owner" : !s.reviewed_at ? "Terms not reviewed" : `Terms review from ${day(s.reviewed_at)} is older than 12 months`;
  return html`<div class="warn-text" style="font-size:12px">${what}: while agents use ${p.name}, compliance control HB-SC-1 is partial.</div>`;
}

function card(p, row, admin) {
  const kind = providerKind(p);
  const [status, tone] = providerStatus(p, row);
  const builtin = p.id === "anthropic" || p.id === "openai";
  const defaultModel = row.default_model || p.default_model;
  const models = p.models?.length ? p.models : [];
  const insecure = p.kind === "openai_compatible" && p.location === "self_hosted" ? plainHttp(p.base_url) : null;
  const defaultCaps = defaultModel ? p.caps?.[defaultModel] ?? p.capabilities?.[defaultModel] : null;
  return html`<article class="provider" data-provider="${p.id}" aria-labelledby="prov-${p.id}-name">
    <div class="row" style="gap:6px;flex-wrap:wrap"><b id="prov-${p.id}-name">${p.name}</b>${badge(KIND_LABELS[kind], kind === "local" ? "info" : "")}
      ${badge(p.location === "third_party" ? "cloud" : "self-hosted", p.location === "third_party" ? "" : "info")}${badge(status, tone)}
      ${insecure ? badge(`unencrypted (http) to ${insecure}`, "warn") : ""}
      <span class="spacer"></span>
      <span class="row" style="gap:4px" data-min-role="admin">
        <button type="button" class="btn sm" data-act="prov-test" data-id="${p.id}">${icon("activity")}Test</button>
        <button type="button" class="icon-btn sm" data-act="prov-edit" data-id="${p.id}" title="Edit" aria-label="Edit ${p.name}">${icon("edit")}</button>
        ${builtin ? "" : html`<button type="button" class="icon-btn sm danger" data-act="prov-remove" data-id="${p.id}" title="Remove" aria-label="Remove ${p.name}">${icon("trash")}</button>`}</span></div>
    ${kind === "anthropic" || kind === "openai" ? "" : html`<div class="url mono">${p.base_url}</div>`}
    <div class="faint" style="font-size:12px">${row.reason && row.available === false && /^no api key/i.test(row.reason)
      ? html`<span class="warn-text">${row.reason[0].toUpperCase()}${row.reason.slice(1)}</span>`
      : html`${keyLine(p)}${row.reason && row.available === false ? html` - <span class="warn-text">${row.reason}</span>` : ""}`}</div>
    <div class="faint" style="font-size:12px">Default model: ${defaultModel ? html`<span class="mono">${defaultModel}</span>` : "none"}
      ${p.kind === "openai_compatible" ? html` - ${p.tools ? "tool calling on" : "tool calling off"} - timeout ${p.timeout}s` : ""}
      ${p.requests_per_minute ? ` - at most ${p.requests_per_minute} requests per minute` : ""}${p.max_concurrency && p.max_concurrency !== 4 ? ` - ${p.max_concurrency} calls at a time` : ""}
      ${p.location_confirmed ? " - marked self-hosted by an administrator" : ""}</div>
    ${defaultModel ? "" : html`<div class="warn-text" style="font-size:12px">No default model: agents that use ${p.name} without choosing a model cannot run on it. ${admin ? "Edit it to pick one" : "An administrator picks one"}${models.length ? " from the tested list" : ""}.</div>`}
    ${defaultModel && admin && kind !== "anthropic" && capsUnknown(defaultCaps) ? html`<div class="row" style="gap:6px;font-size:12px"><span class="faint">Tools and JSON support of ${defaultModel} are not known yet.</span>
      <button type="button" class="btn sm" data-act="prov-probe" data-id="${p.id}" data-model="${defaultModel}">${icon("activity")}Check tools and JSON</button></div>` : ""}
    ${kind === "openai" && !p.api_key_set && p.key_source !== "env" ? html`<div class="faint" style="font-size:12px">${SUBSCRIPTION}</div>` : ""}
    ${p.location === "third_party" ? supplierLine(p) : ""}
    <div class="faint" style="font-size:12px;overflow-wrap:anywhere" aria-live="polite" data-test-result="${p.id}">${p.last_test ? html`Last test ${timeAgo(p.last_test.at)}: ${p.last_test.detail}` : ""}</div>
    ${models.length ? html`<details><summary class="faint" style="cursor:pointer;font-size:12px">${models.length} model${models.length === 1 ? "" : "s"}</summary>
      <ul class="model-list">${models.map((m) => modelRow(p, m, admin))}</ul></details>` : ""}
  </article>`;
}

function view(pv, admin) {
  const status = pv.llm || pv.anthropic || {};
  const rows = Object.fromEntries((status.providers || []).map((r) => [r.id, r]));
  const records = pv.records || [...(pv.builtin || []), ...(pv.providers || [])];
  return html`<header><h2>AI providers</h2><span class="spacer"></span><div class="card-actions" data-slot="home"></div>
      <button type="button" class="btn sm" data-act="prov-add" data-min-role="admin">${icon("plus")}Add provider</button></header>
    <p class="muted" style="margin-bottom:12px">Agents run on Claude, OpenAI (or Azure OpenAI), a model server with an OpenAI-compatible API (Ollama, LM Studio,
      vLLM, llama.cpp server), or on rules. Which one is set under Model choice, per team and per agent${status.default?.provider_label ? html` - agents without a
      choice now run on <b>${status.default.provider_label}</b>${status.default.model ? html` (<span class="mono">${status.default.model}</span>)` : ""}` : ""}.</p>
    <div class="stack" style="gap:8px">${records.map((p) => card(p, rows[p.id] || {}, admin))}
      ${records.some((p) => p.kind === "openai_compatible") ? "" : html`<p class="faint" style="font-size:12.5px">No local model servers yet. Add one to run agents on your own hardware.</p>`}</div>`;
}

/** Renders the panel into `el`, keeps it current on provider events, and wires its actions. */
export async function mount(el, ctx) {
  let pv = await get("/llm/providers");
  const admin = can("admin");
  const draw = () => setHTML(el, view(pv, admin));
  const load = async () => {
    pv = await get("/llm/providers");
    if (el.isConnected) draw();
  };
  const find = (id) => (pv.records || []).find((p) => p.id === id);

  async function test(id, btn) {
    const label = btn?.innerHTML;
    if (btn) { btn.disabled = true; btn.textContent = "Testing..."; }
    try {
      const r = await post(`/llm/providers/${encodeURIComponent(id)}/test`);
      toast(`${r.provider?.name || id}: ${r.detail}`, r.ok ? "ok" : "bad");
    } catch (err) {
      toast(err.message, "bad");
    } finally {
      if (btn?.isConnected) { btn.disabled = false; btn.innerHTML = label; }
    }
    await load();
    el.querySelector(`[data-provider="${CSS.escape(id)}"] [data-act="prov-test"]`)?.focus();
  }

  async function probe(id, model, btn) {
    if (btn) { btn.disabled = true; btn.setAttribute("aria-busy", "true"); }
    const said = (v) => (v === true ? "yes" : v === false ? "no" : "unknown");
    try {
      const r = await post(`/llm/providers/${encodeURIComponent(id)}/probe`, { model });
      toast(`${model}: tools ${said(r.caps.tools)}, JSON ${said(r.caps.json_schema)} (${r.tokens} tokens)`, "ok");
    } catch (err) {
      toast(err.message, "bad");
    }
    await load();
    const card = el.querySelector(`[data-provider="${CSS.escape(id)}"]`); // the panel was redrawn: keep the place
    const again = card?.querySelector(`[data-act="prov-probe"][data-model="${CSS.escape(model)}"]`);
    if (again?.closest("details")) again.closest("details").open = true;
    (again || card?.querySelector('[data-act="prov-test"]'))?.focus();
  }

  function pickKind() {
    modal({
      title: "Add an AI provider", submit: "Next", minRole: "admin",
      body: html`<fieldset class="plain"><legend class="sr-only">Kind of provider</legend><div class="stack" style="gap:10px">
        ${ADD.map(([value, title, text], n) => html`<label class="radio-card"><input type="radio" name="kind" value="${value}" ${n === 0 ? "checked" : ""}>
          <div><b>${title}</b><p class="muted">${text}</p></div></label>`)}</div></fieldset>
        <p class="faint" style="font-size:12.5px;margin-top:10px">Claude and OpenAI are built in: set their API key on their cards.</p>`,
      onSubmit(data) {
        const kind = String(data.get("kind") || "local");
        setTimeout(() => form(null, kind), 0);
      },
    });
  }

  function form(p, kindHint) {
    const kind = p ? providerKind(p) : kindHint;
    const id = `pf${++uid}`;
    const builtin = p && (p.id === "anthropic" || p.id === "openai");
    const local = kind === "local" || kind === "cloud";
    const models = [...new Set([...(p?.pinned_models || []), ...(p?.models || []), ...(kind === "anthropic" ? CLAUDE_MODELS : [])])];
    const title = p ? `Edit ${p.name}` : { local: "Add a local model server", azure: "Add an Azure OpenAI resource", cloud: "Add an OpenAI-compatible cloud service" }[kind];
    const keyHint = kind === "anthropic" ? "ANTHROPIC_API_KEY (or ant auth login) on the hub machine overrides a stored key."
      : kind === "openai" ? "OPENAI_API_KEY on the hub machine overrides a stored key."
        : "Stored encrypted and only ever sent to this base URL's address; it is never shown again. Changing the address requires entering it again.";
    const switchedOn = !!(p && (p.enabled || (p.id === "openai" && p.key_source === "env" && p.updated_by === "hub")));
    const m = modal({
      title, wide: true, minRole: "admin", submit: p ? "Save" : "Add and test",
      body: html`
        ${kind === "anthropic" ? html`<p class="muted" style="margin-bottom:12px">Claude through the Anthropic API at the fixed address <code>https://api.anthropic.com</code>.</p>` : ""}
        ${kind === "openai" ? html`<div class="notice" style="margin-bottom:12px">${icon("key")}<div class="muted">${SUBSCRIPTION}
          <a href="https://platform.openai.com/api-keys" target="_blank" rel="noopener noreferrer">Create an API key</a>. Requests go to the fixed address
          <code>https://api.openai.com/v1</code> (Responses API) and are not stored at OpenAI.</div></div>` : ""}
        ${kind === "azure" ? html`<p class="muted" style="margin-bottom:12px">Uses the Azure OpenAI v1 API (Responses) with an API key. Models are your deployment names.</p>` : ""}
        ${local ? html`<p class="muted" style="margin-bottom:12px">A model server with an OpenAI-compatible API. The hub calls <code>{base URL}/chat/completions</code>
          with tool definitions and lists models from <code>{base URL}/models</code>.</p>` : ""}
        <div class="form-grid">
          ${builtin ? "" : lfield("Name", html`<input id="${id}-name" name="name" required maxlength="80" value="${p?.name || ""}" placeholder="${kind === "azure" ? "e.g. Azure production" : "e.g. Ollama on gpu-01"}">`, "", `${id}-name`)}
          ${lfield(kind === "azure" ? "Default deployment" : "Default model", html`<input id="${id}-model" name="default_model" list="${id}-models" maxlength="200" value="${p?.default_model || ""}"
              placeholder="${kind === "azure" ? "your deployment name" : kind === "openai" ? "e.g. gpt-6-luna" : kind === "anthropic" ? "default: HUB_MODEL" : "e.g. llama3.1:8b"}">
            <datalist id="${id}-models">${models.map((x) => html`<option value="${x}">`)}</datalist>`,
          kind === "azure" ? "The deployment agents use unless they choose another." : "Test the provider to list its models.", `${id}-model`)}
        </div>
        ${kind === "anthropic" || kind === "openai" ? "" : lfield("Base URL", html`<input id="${id}-url" name="base_url" required maxlength="500" class="mono"
            value="${p?.base_url || (kind === "local" ? pv.default_base_url : "")}" placeholder="${kind === "azure" ? "https://<resource>.openai.azure.com/openai/v1" : "https://llm.example.com/v1"}">`,
          kind === "azure" ? "https://<resource>.openai.azure.com/openai/v1 or https://<resource>.services.ai.azure.com/openai/v1" : kind === "local" ? SERVERS : "Must use https.", `${id}-url`)}
        ${local ? html`<div class="notice" style="margin-bottom:12px" data-where aria-live="polite"></div>` : ""}
        ${lfield(`API key${local ? " (optional)" : ""}`, html`<input id="${id}-key" name="api_key" type="password" autocomplete="new-password" maxlength="4096"
            placeholder="${p?.api_key_set ? "Stored - leave empty to keep it" : local ? "Most local servers need none" : "Paste the API key"}" aria-describedby="${id}-key-hint">`, keyHint, `${id}-key`)}
        ${p?.api_key_set ? html`<label class="check" style="margin-bottom:12px"><input type="checkbox" name="clear_api_key"><span>Remove the stored API key</span></label>` : ""}
        ${lfield(kind === "azure" ? "Deployments (one per line)" : "Models shown first (one per line, optional)", html`<textarea id="${id}-pinned" name="pinned_models" rows="3" class="mono">${(p?.pinned_models || []).join("\n")}</textarea>`,
          kind === "azure" ? "Agents can choose among these; the deployment list is fetched when Azure provides one." : "Pinned in the model pickers.", `${id}-pinned`)}
        <div class="form-grid">
          ${kind === "anthropic" ? "" : lfield("Timeout (seconds)", html`<input id="${id}-timeout" type="number" name="timeout" min="5" max="3600" step="1" value="${p?.timeout ?? 300}">`, "", `${id}-timeout`)}
          ${lfield("Calls at a time", html`<input id="${id}-conc" type="number" name="max_concurrency" min="1" max="64" step="1" value="${p?.max_concurrency ?? 4}">`,
            "More calls wait their turn (1-64).", `${id}-conc`)}
          ${lfield("Requests per minute", html`<input id="${id}-rpm" type="number" name="requests_per_minute" min="1" max="100000" step="1" value="${p?.requests_per_minute ?? ""}" placeholder="No limit">`,
            "More wait up to 30 seconds, then fail as rate-limited.", `${id}-rpm`)}
          ${p ? html`<label class="check" style="align-self:center"><input type="checkbox" name="enabled" ${switchedOn ? "checked" : ""}>
            <span>Switched on<span class="faint" style="display:block;font-size:12px">Off: agents that use it move on to the next choice.</span></span></label>` : ""}
        </div>
        <fieldset class="plain" data-supplier style="margin-top:14px" ${kind === "local" ? "hidden" : ""}><legend style="font-weight:600;font-size:13px;margin-bottom:6px">Supplier (cloud providers, compliance control HB-SC-1)</legend>
          <div class="form-grid">
            ${lfield("Supplier owner", html`<input id="${id}-owner" name="supplier_owner" maxlength="200" list="${id}-people" value="${p?.supplier?.owner || ""}" placeholder="Who answers for this supplier">
              <datalist id="${id}-people"></datalist>`, "A person from People, or any name.", `${id}-owner`)}
            ${lfield("Terms / data processing agreement reviewed on", html`<input id="${id}-reviewed" type="date" name="supplier_reviewed" max="${day(Date.now() / 1000)}"
              value="${p?.supplier?.reviewed_at ? day(p.supplier.reviewed_at) : ""}">`, "Review at least every 12 months.", `${id}-reviewed`)}
          </div>
          ${lfield("Supplier notes", html`<input id="${id}-snotes" name="supplier_notes" maxlength="500" value="${p?.supplier?.notes || ""}" placeholder="e.g. DPA signed, data region EU">`, "", `${id}-snotes`)}
        </fieldset>
        ${local ? html`<div class="form-grid">
          ${lfield("Structured output", html`<select id="${id}-so" name="structured_output">${options(STRUCTURED, p?.structured_output || "auto")}</select>`, "How the hub asks for JSON answers.", `${id}-so`)}
          <div class="stack" style="gap:6px;align-self:center">
            <label class="check"><input type="checkbox" name="tools" ${p && !p.tools ? "" : "checked"}><span>Send tool definitions<span class="faint" style="display:block;font-size:12px">Turn off for models without tool calling.</span></span></label>
            <label class="check"><input type="checkbox" name="send_effort" ${p?.send_effort ? "checked" : ""}><span>Send the reasoning effort<span class="faint" style="display:block;font-size:12px">For servers that accept reasoning_effort.</span></span></label></div>
        </div>` : ""}`,
      async onSubmit(data) {
        const body = {};
        if (!builtin) body.name = String(data.get("name") || "").trim();
        body.default_model = String(data.get("default_model") || "").trim();
        const pinned = parseModels(data.get("pinned_models"));
        if (p || pinned.length) body.pinned_models = pinned;
        if (data.has("base_url")) body.base_url = String(data.get("base_url") || "").trim();
        if (data.has("timeout")) {
          const timeout = Number(data.get("timeout"));
          if (!Number.isFinite(timeout) || timeout < 5 || timeout > 3600) {
            toast("The timeout is 5 to 3600 seconds", "bad");
            m.el.querySelector(`#${id}-timeout`)?.focus();
            return true;
          }
          body.timeout = timeout;
        }
        const conc = Number(data.get("max_concurrency") || 4);
        const rpm = String(data.get("requests_per_minute") || "").trim();
        if (!Number.isInteger(conc) || conc < 1 || conc > 64 || (rpm && !(Number.isInteger(Number(rpm)) && Number(rpm) >= 1 && Number(rpm) <= 100000))) {
          toast("Calls at a time: 1-64; requests per minute: empty or 1-100000", "bad");
          return true;
        }
        body.max_concurrency = conc;
        body.requests_per_minute = rpm ? Number(rpm) : 0; // 0: no limit
        if (p && (data.get("enabled") === "on") !== switchedOn) body.enabled = data.get("enabled") === "on"; // a new key switches OpenAI on
        if (local) {
          body.tools = data.get("tools") === "on";
          body.send_effort = data.get("send_effort") === "on";
          body.structured_output = String(data.get("structured_output") || "auto");
          const computed = hostLocation(body.base_url);
          if (computed === "third_party") body.confirm_self_hosted = data.get("self_hosted") === "on";
          else if (computed === "self_hosted") body.location = data.get("cloud_proxy") === "on" ? "third_party" : "self_hosted";
        }
        const supplier = { owner: String(data.get("supplier_owner") || "").trim(), notes: String(data.get("supplier_notes") || "").trim(),
          reviewed_at: data.get("supplier_reviewed") ? Date.parse(`${data.get("supplier_reviewed")}T12:00:00Z`) / 1000 : null };
        const before = p?.supplier || { owner: "", notes: "", reviewed_at: null };
        const sameDay = (a, b) => (a ? day(a) : "") === (b ? day(b) : "");
        if (!m.el.querySelector("[data-supplier]").hidden
            && (supplier.owner !== (before.owner || "") || supplier.notes !== (before.notes || "") || !sameDay(supplier.reviewed_at, before.reviewed_at))) {
          body.supplier = sameDay(supplier.reviewed_at, before.reviewed_at) ? { ...supplier, reviewed_at: before.reviewed_at ?? null } : supplier;
        }
        const key = String(data.get("api_key") || "");
        if (key) body.api_key = key;
        if (data.get("clear_api_key") === "on") body.clear_api_key = true;
        if (!builtin && !body.name) {
          toast("Give the provider a name", "bad");
          m.el.querySelector(`#${id}-name`)?.focus();
          return true;
        }
        if (body.base_url === "") {
          toast("Enter the base URL", "bad");
          m.el.querySelector(`#${id}-url`)?.focus();
          return true;
        }
        if (!p) {
          body.kind = kind === "azure" ? "openai" : "openai_compatible";
          if (kind === "azure") body.variant = "azure";
        }
        const saved = p ? await patch(`/llm/providers/${encodeURIComponent(p.id)}`, body) : await post("/llm/providers", body);
        toast(`${saved.name} ${p ? "saved" : "added"}`, "ok");
        if (p) await load();
        else test(saved.id);
      },
    });
    get("/people?brief=1").then((r) => {
      const list = m.el.querySelector(`#${id}-people`);
      if (list) setHTML(list, html`${(r.people || []).filter((x) => x.status === "active").map((x) => html`<option value="${x.display_name}">`)}`);
    }).catch(() => {}); // People may be empty or unreadable: free text still works
    if (!local) return;
    // where the server runs: computed from the address; a public address may be confirmed as the administrator's own
    const box = m.el.querySelector("[data-where]");
    const url = m.el.querySelector(`#${id}-url`);
    const hostOf = (value) => { try { return new URL(value).hostname; } catch { return ""; } };
    const savedHost = p ? hostOf(p.base_url) : null;
    let shown = null;
    // the saved marking applies to the saved host only: another host is asked again (never confirmed by default)
    const showWhere = () => {
      const computed = hostLocation(url.value.trim());
      m.el.querySelector("[data-supplier]").hidden = computed !== "third_party" && !(m.el.querySelector('[name="cloud_proxy"]')?.checked);
      const same = hostOf(url.value.trim()) === savedHost;
      const key = `${computed}|${same}`;
      if (key === shown) return;
      shown = key;
      setHTML(box, computed === null ? html`${icon("server")}<div class="muted">Where the server runs follows from its address.</div>`
        : computed === "third_party" ? html`${icon("cloud")}<div><div class="muted">This address is public: the server counts as a <b>cloud provider</b> (third party) and must use https.</div>
            <label class="check" style="margin-top:6px"><input type="checkbox" name="self_hosted" ${same && p?.location_confirmed ? "checked" : ""}><span>This server is ours (self-hosted)<span class="faint" style="display:block;font-size:12px">Logged as a warning: agents on it count as running on your own hardware.</span></span></label></div>`
          : html`${icon("server")}<div><div class="muted">This address is on your own network: the server counts as <b>self-hosted</b>.</div>
            <label class="check" style="margin-top:6px"><input type="checkbox" name="cloud_proxy" ${(same ? p?.location === "third_party" : kind === "cloud") ? "checked" : ""}><span>It forwards to a cloud service (count it as a cloud provider)</span></label></div>`);
    };
    showWhere();
    url.addEventListener("input", showWhere);
    m.el.addEventListener("change", (e) => { // a forwarding proxy to a cloud service is a supplier too
      if (e.target.name === "cloud_proxy") m.el.querySelector("[data-supplier]").hidden = !e.target.checked && hostLocation(url.value.trim()) !== "third_party";
    });
  }

  draw();
  actions(el, {
    "prov-add"() { pickKind(); },
    "prov-edit"(d) {
      const p = find(d.id);
      if (p) form(p);
    },
    "prov-test"(d, btn) { test(d.id, btn); },
    "prov-probe"(d, btn) { probe(d.id, d.model, btn); },
    async "prov-remove"(d) {
      const p = find(d.id);
      if (!p || !(await confirmDialog(`Remove ${p.name}?`, "Agents can no longer run on it. Providers still used by agents or a default cannot be removed.", "Remove"))) return;
      try {
        await del(`/llm/providers/${encodeURIComponent(p.id)}`);
        toast(`${p.name} removed`, "ok");
      } catch (err) {
        toast(err.message, "bad");
      }
      await load();
      el.querySelector('[data-act="prov-add"]')?.focus();
    },
  });
  ctx.live(["llm_provider", "llm_provider_removed", "settings"], load, 400);
}
