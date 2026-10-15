// Compliance hub, Frameworks tab: the CyberFundamentals (CyFun) 2025 and 2023 catalogs, self-assessments scored by
// people (implementation and documentation maturity 1-5 per requirement), conformity per level with its reasons, the
// audit pack, and frameworks read from CISO Assistant (read-only, e.g. the CRA). The catalogs hold requirement ids,
// level tags and NIST CSF titles only: the CCB's requirement text is on cyfun.eu. Text read from CISO Assistant is
// shown as text only.
// Routes: #/compliance/frameworks[/<edition>[/<assessment id>[/<view>]]] and #/compliance/frameworks/<ext:tool:id>.
import { del, get, patch, post } from "../api.js";
import { loadPeople, personChip, personOptions } from "../people.js";
import {
  actions, badge, can, confirmDialog, dateTime, debounce, emptyState, field, html, icon, modal, options, raw, setHTML, timeAgo,
  toast,
} from "../ui.js";

const enc = encodeURIComponent;
const BASE = "#/compliance/frameworks";
const LEVELS = ["B", "I", "E"];
const LEVEL_NAMES = { B: "Basic", I: "Important", E: "Essential" };
const VERDICTS = { met: ["met", "ok"], not_met: ["not met", "bad"], incomplete: ["incomplete", "info"] };
const STATUSES = [["in_progress", "In progress"], ["completed", "Completed"], ["archived", "Archived"]];
const STATUS_ICON = { pass: "check", partial: "minus", fail: "x", manual: "edit", na: "minus" };
const EVIDENCE_KINDS = [["control", "Hub control"], ["policy", "Policy"], ["risk", "Risk"], ["url", "Link (http/https)"], ["file", "File kept elsewhere"]];
const EVIDENCE_ICON = { control: "shield", policy: "file", risk: "alert", url: "link", file: "folder" };
const RESULT_TONES = { compliant: "ok", partially_compliant: "warn", non_compliant: "bad", not_applicable: "", not_assessed: "" };
const WORK_FILTERS = [["", "Any status"], ["unscored", "Not scored"], ["scored", "Scored"], ["na", "N/A"], ["below", "Below target"],
  ["nodoc", "Documentation not scored"], ["noowner", "No owner"], ["noevidence", "No evidence"]];
const CATALOG_FILTERS = [["", "Any hub evidence"], ["hub", "With suggested hub controls"], ["hub_failing", "Hub control failing or partial"], ["nohub", "No hub control"]];
const VIEWS = [["requirements", "Requirements"], ["scores", "Scores"], ["gaps", "Gaps & key measures"], ["details", "Details"]];
const GROUP_NAMES = { "": "requirements", K: "key measures", G: "management aspects" };
const HISTORY_LABELS = { implementation: "Implementation", documentation: "Documentation", na: "N/A", na_justification: "N/A justification",
  owner_person_id: "Owner", notes: "Notes", evidence: "Evidence" };
const URL_RE = /^https?:\/\/[^\s/$.?#@][^\s@]*$/i; // as the server checks it: http(s), no user name or password
const THRESHOLDS_NOTE = "The thresholds and the scoring method are taken from the CyFun library copy that ships with CISO Assistant: the CCB's own documents were unreachable, so they are not verified against the CCB originals.";

// ---------- small helpers ----------

/** Two decimals, half up, as the server and the CCB tools show scores; "-" when not scored. */
export function fmt(v) {
  return v === null || v === undefined || v < 0 ? "-" : (Math.round((v + 1e-9) * 100) / 100).toFixed(2);
}
const tone = (m, target) => (m == null || m < 0 ? "" : m >= target ? "ok" : m >= target - 1 ? "warn" : "bad");
const pct = (v) => Math.max(0, Math.min(100, (v / 5) * 100));
const day = (iso) => (iso ? new Date(`${iso}T00:00:00`).toLocaleDateString(undefined, { day: "numeric", month: "long", year: "numeric" }) : "");
const names = (levels) => levels.map((l) => LEVEL_NAMES[l]).join(", ");
const from = (levels) => (levels[0] === "E" ? "E" : `${levels[0]}+`);
const safeHref = (u) => (URL_RE.test(u || "") ? u : null);
const CHEVRON = raw('<svg class="i" viewBox="0 0 24 24" aria-hidden="true"><path d="m9 6 6 6-6 6"/></svg>');
const statusBadge = (s) => badge(s === "na" ? "n/a" : s);

/** A maturity on the 0-5 scale with the target as a tick. */
function meter(m, target, label = "Maturity") {
  const scored = m != null && m >= 0;
  return html`<span class="fw-meter ${tone(m, target)}" role="img" aria-label="${label} ${scored ? fmt(m) : "not scored"}${target ? `, target ${fmt(target)}` : ""}">
    <span style="width:${scored ? pct(m) : 0}%"></span>${target ? html`<i style="left:${pct(target)}%"></i>` : ""}</span>`;
}

const verdictBadge = (v) => badge(...(VERDICTS[v] || [v, ""]));

function levelVerdicts(levels) {
  return html`<span class="fw-verdicts">${levels.map((l) => {
    const [text, t] = VERDICTS[l.verdict] || [l.verdict, ""];
    return html`<span class="badge ${t} ${l.targeted ? "" : "fw-dim"}" title="${LEVEL_NAMES[l.level]}: ${text}${l.targeted ? "" : " (beyond the target level)"}; maturity ${fmt(l.maturity)}">${l.level}<span class="sr-only"> ${LEVEL_NAMES[l.level]} ${text}</span></span>`;
  })}</span>`;
}

/** B / I / E boxes: the levels that require the requirement (levels are cumulative). */
function levelChips(r) {
  const on = LEVELS.filter((l) => r.tags.includes(l));
  return html`<span class="fw-tags" title="Required at ${names(on) || "no level"}">${LEVELS.map((l) => html`<span class="fw-lvl ${on.includes(l) ? "on" : ""}" aria-hidden="true">${l}</span>`)}<span class="sr-only">Required at ${names(on)}</span></span>`;
}

function measureBadges(r) {
  return html`${r.key_measure.length ? html`<span class="badge warn" title="Key measure at ${names(r.key_measure)}">${icon("key")}Key ${from(r.key_measure)}</span>` : ""}
    ${r.management.length ? html`<span class="badge info" title="Management aspect at ${names(r.management)}">Mgmt ${from(r.management)}</span>` : ""}`;
}

function sourceNote(text, verified) {
  const unverified = !verified || /^UNVERIFIED/i.test(text);
  return html`<div class="notice ${unverified ? "warn" : ""}" style="margin-top:10px;font-size:12.5px">${icon(unverified ? "alert" : "file")}
    <div>${text}. <span class="muted">${THRESHOLDS_NOTE}</span></div></div>`;
}

function transitionNotice(t) {
  if (!t) return "";
  return html`<div class="notice warn" style="margin-bottom:14px">${icon("clock")}<div><b>Transition period.</b> ${t.note}
    ${t.open ? "" : html` <b>New assessments of this edition are no longer possible (allowed until ${day(t.assess_until)}).</b>`}</div></div>`;
}

const notFound = (title, text) => html`<section class="card">${emptyState("alert", title, text, html`<a class="btn" href="${BASE}">${icon("arrow")}Frameworks</a>`)}</section>`;

/** ref -> {r, fn, cat, sub} over a built-in catalog's tree. */
function indexOf(fw) {
  const idx = {};
  for (const fn of fw.tree) for (const cat of fn.categories) for (const sub of cat.subcategories) for (const r of sub.requirements) idx[r.ref_id] = { r, fn, cat, sub };
  return idx;
}

// ---------- the requirement tree, shared by the catalog browser and the assessment workspace ----------

function baseMatch(r, f, idx) {
  if (f.level && !r.tags.includes(f.level)) return false;
  if (f.key && !(f.level ? r.key_measure.includes(f.level) : r.key_measure.length)) return false;
  if (f.mgmt && !(f.level ? r.management.includes(f.level) : r.management.length)) return false;
  if (f.q) {
    const { cat, sub } = idx[r.ref_id];
    if (!`${r.ref_id} ${sub.title} ${cat.id} ${cat.title}`.toLowerCase().includes(f.q.toLowerCase())) return false;
  }
  return true;
}

const WORK_TESTS = {
  unscored: (e) => !e.na && e.implementation == null,
  scored: (e) => !e.na && e.implementation != null,
  na: (e) => e.na,
  below: (e, gaps) => gaps.has(e.ref_id),
  nodoc: (e) => !e.na && e.implementation != null && e.documentation == null,
  noowner: (e) => !e.owner_person_id,
  noevidence: (e) => !e.evidence.length,
};
const HUB_TESTS = {
  hub: (list) => list.length > 0,
  hub_failing: (list) => list.some((s) => s.status === "fail" || s.status === "partial"),
  nohub: (list) => !list.length,
};

/** function -> category -> subcategory -> rows of the requirements `keep` accepts. */
function treeView(fw, keep, { row, collapsed, fnScore, catScore }) {
  const out = [];
  for (const fn of fw.tree) {
    const cats = fn.categories.map((cat) => {
      const subs = cat.subcategories.map((sub) => ({ sub, reqs: sub.requirements.filter(keep) })).filter((s) => s.reqs.length);
      return { cat, subs, n: subs.reduce((a, s) => a + s.reqs.length, 0) };
    }).filter((c) => c.n);
    if (!cats.length) continue;
    const n = cats.reduce((a, c) => a + c.n, 0);
    out.push(html`<details class="fw-fn" data-fn="${fn.id}" ${collapsed.has(fn.id) ? "" : "open"}>
      <summary><span class="fw-chev">${CHEVRON}</span><span class="fw-fn-id">${fn.id}</span><b>${fn.title}</b>
        <span class="faint" style="font-size:12px">${n} requirement${n === 1 ? "" : "s"}</span><span class="spacer"></span>${fnScore?.(fn.id) || ""}</summary>
      ${cats.map(({ cat, subs }) => html`<div class="fw-cat"><div class="fw-cat-head"><code>${cat.id}</code><b>${cat.title}</b><span class="spacer"></span>${catScore?.(cat.id) || ""}</div>
        ${subs.map(({ sub, reqs }) => html`<div class="fw-sub"><span class="mono">${sub.id}</span>${sub.title}</div>${reqs.map(row)}`)}</div>`)}
    </details>`);
  }
  return out;
}

function filterBar(fw, f, statusChoices) {
  return html`<div class="row filters fw-filters">
    <select data-filter="level" class="input-sm" aria-label="Level">${options([["", "All levels"], ...fw.levels.map((l) => [l.id, `${l.name} (${l.requirements})`])], f.level)}</select>
    <label class="check"><input type="checkbox" data-filter="key" ${f.key ? "checked" : ""}> Key measures</label>
    ${fw.levels.some((l) => l.management_aspects) ? html`<label class="check"><input type="checkbox" data-filter="mgmt" ${f.mgmt ? "checked" : ""}> Management aspects</label>` : ""}
    <select data-filter="status" class="input-sm" aria-label="Status">${options(statusChoices, f.status)}</select>
    <span class="spacer"></span><span class="faint" style="font-size:12.5px" data-part="count" aria-live="polite"></span>
    <input data-filter="q" value="${f.q}" placeholder="Search id or title..." style="max-width:240px" aria-label="Search requirements"></div>`;
}

/** Filter inputs (rendered once per view) update `f` and call onChange; `collapsed` follows the function sections. */
function bindTree(el, f, collapsed, onChange) {
  const typed = debounce(onChange, 160);
  el.addEventListener("input", (e) => {
    if (e.target.dataset?.filter !== "q") return;
    f.q = e.target.value.trim();
    typed();
  });
  el.addEventListener("change", (e) => {
    const k = e.target.dataset?.filter;
    if (!k || k === "q") return;
    f[k] = e.target.type === "checkbox" ? e.target.checked : e.target.value;
    onChange();
  });
  el.addEventListener("toggle", (e) => {
    const d = e.target;
    if (d.matches?.("details.fw-fn")) d.open ? collapsed.delete(d.dataset.fn) : collapsed.add(d.dataset.fn);
  }, true);
}

/** The focused control as a selector, to focus its replacement after a re-render. */
function focusKey(el) {
  const a = document.activeElement;
  if (!a || !el.contains(a)) return null;
  if (a.dataset.score) return `select[data-score="${a.dataset.score}"][data-ref="${CSS.escape(a.dataset.ref)}"]`;
  if (a.dataset.act && a.dataset.ref) return `[data-act="${a.dataset.act}"][data-ref="${CSS.escape(a.dataset.ref)}"]`;
  return null;
}

// ---------- entry point ----------

/** Renders the Frameworks tab into `el` (below the Compliance hub's tabs); `params` follow "frameworks" in the route. */
export async function renderFrameworks(el, ctx, params) {
  const [first, second, third] = params;
  const list = await get("/frameworks");
  if (!el.isConnected) return;
  if (first?.startsWith("ext:")) return renderExternal(el, ctx, first);
  const edition = first || list.default;
  if (!list.frameworks.some((f) => f.kind === "builtin" && f.id === edition)) {
    ctx.crumb("Compliance hub / framework not found");
    setHTML(el, notFound("Framework not found", "Atrium ships CyFun 2025 and CyFun 2023; other frameworks come from a connected CISO Assistant."));
    return;
  }
  if (second) return renderWorkspace(el, ctx, edition, second, third, list);
  return renderEdition(el, ctx, edition, list);
}

// ---------- edition page: assessments, catalog browser, about, CISO Assistant ----------

function editionBar(list, fid) {
  const builtins = list.frameworks.filter((f) => f.kind === "builtin");
  return html`<div class="fw-bar"><div class="seg" aria-label="Edition">${builtins.map((f) => html`<button type="button" class="${f.id === fid ? "active" : ""}"
      aria-pressed="${String(f.id === fid)}" data-act="go" data-href="${BASE}/${f.id}">${f.short_name}${f.default ? html` <span class="badge accent">current</span>`
      : f.transition ? html` <span class="badge warn" title="${f.transition.note}">until ${f.transition.assess_until}</span>` : ""}</button>`)}</div>
    <span class="spacer"></span>
    <span class="faint" style="font-size:12.5px">Scores are your judgement: Atrium suggests hub controls as evidence and never sets a score.</span></div>`;
}

function syncState(a, sync) {
  const hit = sync.find((c) => c.assessments[a.id]);
  if (hit) return html`<span class="row" style="gap:4px;font-size:12.5px" title="Compliance assessment ${hit.assessments[a.id].external_id} in ${hit.tool_name}">${icon("check")}${timeAgo(hit.assessments[a.id].synced_at)}</span>`;
  if (a.status !== "archived" && sync.some((c) => c.push_enabled)) return html`<span class="faint" style="font-size:12px">next push</span>`;
  return html`<span class="faint">-</span>`;
}

function assessmentsCard(fw, list) {
  const items = fw.assessments;
  const open = !fw.transition || fw.transition.open;
  return html`<header><h2>Self-assessments</h2>${open ? html`<button type="button" class="btn sm primary" data-act="new" data-min-role="operator">${icon("plus")}New assessment</button>` : ""}</header>
    ${items.length ? html`<div class="table-wrap" style="margin-top:10px"><table class="table"><thead><tr><th>Assessment</th><th>Target</th><th>Status</th><th>Assessed</th>
        <th>Maturity</th><th>Levels</th><th>Updated</th>${list.sync.length ? html`<th>CISO Assistant</th>` : ""}</tr></thead><tbody>
      ${items.map((a) => html`<tr class="clickable ${a.status === "archived" ? "stale" : ""}" data-act="go" data-href="${BASE}/${enc(fw.id)}/${enc(a.id)}">
        <td><a href="${BASE}/${enc(fw.id)}/${enc(a.id)}"><b>${a.name}</b></a>${a.stale ? html` ${badge("older than 12 months", "warn")}` : ""}
          <div class="faint" style="font-size:12px">started by ${a.created_by} ${timeAgo(a.created_at)}</div></td>
        <td>${a.target_name}</td><td>${badge(a.status)}</td>
        <td style="min-width:110px"><div class="progress" style="margin-bottom:3px"><span style="width:${a.progress.percent}%"></span></div><span class="faint" style="font-size:12px">${a.progress.percent}%</span></td>
        <td>${fmt(a.maturity)}</td><td>${levelVerdicts(a.levels)}</td>
        <td class="faint" title="${dateTime(a.updated_at)}">${timeAgo(a.updated_at)}</td>
        ${list.sync.length ? html`<td>${syncState(a, list.sync)}</td>` : ""}</tr>`)}
      </tbody></table></div>`
    : html`<div style="padding:0 16px 8px">${emptyState("shield", "No self-assessment yet", `Score each ${fw.short_name} requirement on implementation and documentation maturity (1-5) and see whether you reach Basic, Important or Essential.`)}</div>`}`;
}

function thresholdsTable(fw) {
  const c = fw.conformity.levels;
  const mgmt = fw.levels.some((l) => l.management_aspects);
  return html`<div class="table-wrap"><table class="table compact"><thead><tr><th>Level</th><th>Maturity &ge;</th><th>Each key measure &ge;</th><th>Each category &ge;</th>
      <th>N/A at most</th><th>N/A key measures</th>${mgmt ? html`<th>N/A management</th>` : ""}</tr></thead>
    <tbody>${LEVELS.map((l) => html`<tr><td>${LEVEL_NAMES[l]}</td><td>${fmt(c[l].maturity_min)}</td><td>${fmt(c[l].key_measure_min)}</td>
      <td>${c[l].category_min == null ? "-" : fmt(c[l].category_min)}</td><td>${c[l].na_max}</td><td>${c[l].na_max_key}</td>
      ${mgmt ? html`<td>${c[l].na_max_management ?? "-"}</td>` : ""}</tr>`)}</tbody></table></div>
    <p class="faint" style="font-size:12px;margin-top:6px">A requirement's maturity is the average of its implementation and documentation maturity (documentation not scored counts as 1).
      N/A counts as ${fmt(fw.conformity.na_counts_as)}. Group and category scores are averages of averages over the framework tree. A level is met only when every rule holds and every requirement of the level is scored or N/A.</p>`;
}

function aboutCard(fw) {
  const s = fw.source;
  return html`<header><h2>${fw.name}</h2>${fw.default ? badge("current edition", "accent") : badge("previous edition", "warn")}</header>
    <dl class="kv">
      <dt>Publisher</dt><dd>${fw.publisher}</dd>
      <dt>Based on</dt><dd>${fw.based_on}</dd>
      <dt>Structure</dt><dd>${fw.counts.requirements} requirements in ${fw.counts.functions} functions, ${fw.counts.categories} categories and ${fw.counts.subcategories} subcategories</dd>
      <dt>Levels</dt><dd>${fw.levels.map((l) => html`<div>${l.name}: ${l.requirements} requirements, ${l.key_measures_count} key measures${fw.counts[l.management_aspects] ? `, ${fw.counts[l.management_aspects]} management aspects` : ""}</div>`)}</dd>
      <dt>Source</dt><dd>${s.library_name}, version ${s.version} (${s.publication_date}), provider ${s.provider}, packaged by ${s.packager}
        <div class="faint mono" style="font-size:11.5px">${s.library_urn}</div></dd>
      <dt>Titles</dt><dd>${fw.titles_source}${fw.own_titles?.length ? `; written for Atrium: ${fw.own_titles.join(", ")}` : ""}</dd>
      ${fw.corrections?.length ? html`<dt>Corrected ids</dt><dd>${fw.corrections.map((c) => html`<div><code>${c.library_ref_id}</code> &rarr; <code>${c.ref_id}</code> <span class="faint">${c.reason}</span></div>`)}</dd>` : ""}
    </dl>
    <p class="faint" style="font-size:12px;margin-top:10px">${fw.notice} <a href="${fw.text_url}" target="_blank" rel="noopener noreferrer">cyfun.eu ${icon("external")}</a></p>
    <h3 style="margin:14px 0 6px">Conformity per level</h3>
    ${thresholdsTable(fw)}
    ${sourceNote(fw.conformity_source, fw.conformity_verified_against_library)}`;
}

function libraryChip(key, conn) {
  const name = conn.library_names[key] || key;
  const state = conn.loaded[key];
  if (state === null || state === undefined) return html`<span class="badge" title="Not read yet">${name}: not read yet</span>`;
  return state ? html`<span class="badge ok">${icon("check")}${name} loaded</span>` : html`<span class="badge">${name} not loaded</span>`;
}

function flowLine(label, flow, none) {
  if (!flow) return html`<div class="faint" style="font-size:12.5px">${label}: ${none}</div>`;
  const counts = flow.counts ? Object.entries(flow.counts).filter(([, n]) => n).map(([k, n]) => `${n} ${k}`).join(", ") : "";
  return html`<div style="font-size:12.5px">${label}: ${badge(flow.status)} ${flow.last_run ? html`<span class="faint" title="${dateTime(flow.last_run)}">last run ${timeAgo(flow.last_run)}</span>` : html`<span class="faint">not run yet</span>`}
    ${flow.ok === false ? html` <span style="color:var(--bad)">${flow.error || "failed"}</span>` : counts ? html` <span class="faint">(${counts})</span>` : ""}</div>`;
}

function externalAssessments(list) {
  if (!list.length) return html`<span class="faint">no compliance assessment of it there</span>`;
  return html`${list.map((a) => html`<div class="row" style="gap:6px;font-size:12.5px"><span>${a.name || a.external_id}</span>${a.status ? badge(a.status) : ""}
    ${a.scores?.maturity != null ? html`<span class="faint">maturity ${fmt(a.scores.maturity)}</span>` : ""}
    ${Object.entries(a.results || {}).filter(([, n]) => n).map(([k, n]) => html`<span class="badge ${RESULT_TONES[k] || ""}">${n} ${k.replace(/_/g, " ")}</span>`)}</div>`)}`;
}

/** CISO Assistant: per connection the libraries loaded there, the read and send flows; the edition's state there. */
function syncCard(list, fw) {
  const externals = list.frameworks.filter((f) => f.kind === "external");
  const here = fw?.ciso_assistant || [];
  return html`<header><h2>CISO Assistant</h2><span class="faint" style="font-size:12px">framework sync</span></header>
    ${list.sync.length ? html`<div class="stack" style="gap:10px">${list.sync.map((c) => html`<div class="sub-card">
        <h3 style="margin-bottom:8px">${icon("link")}<a href="#/tools/${enc(c.tool_id)}">${c.tool_name}</a>
          ${c.pulled_at ? html`<span class="faint" style="font-size:12px;font-weight:500">${c.frameworks} framework${c.frameworks === 1 ? "" : "s"} read ${timeAgo(c.pulled_at)}</span>` : ""}</h3>
        <div class="row" style="gap:6px;margin-bottom:8px">${Object.keys(c.loaded).map((k) => libraryChip(k, c))}</div>
        ${flowLine("Reading frameworks", c.pull_flow, "no flow yet - the GRC Supervisor proposes one once the connection test passes; approve it in Approvals")}
        ${c.push_enabled ? flowLine("Sending self-assessments", c.push_flow, "allowed - the Hub Supervisor proposes the flow after the next successful connection test; approve it in Approvals")
          : html`<div class="faint" style="font-size:12.5px">Sending self-assessments: off. An administrator can allow "Send CyFun self-assessments" in the
            <a href="#/tools/${enc(c.tool_id)}/connection">connection</a>; only then are results and maturity scores written there.</div>`}</div>`)}</div>
      <p class="faint" style="font-size:12px;margin-top:10px">Atrium never imports libraries into CISO Assistant: load CyFun 2025, CyFun 2023 or the CRA from its library store yourself.
        Frameworks other than CyFun appear here read-only, with their requirement tree and CISO Assistant's assessment status.</p>`
    : html`<p class="muted" style="font-size:13px">No CISO Assistant connection. Set one up in its tool's Connection tab to see the frameworks loaded there
      (for example the Cyber Resilience Act) and, if an administrator allows it, to send these self-assessments there.</p>`}
    ${here.length ? html`<h3 style="margin:14px 0 6px">${fw.short_name} in CISO Assistant</h3>${here.map((x) => html`<div class="sub-card" style="margin-bottom:8px">
        <div class="row" style="gap:6px;margin-bottom:4px"><b>${x.name}</b><span class="faint" style="font-size:12px">in ${x.source.tool_name}, ${x.counts.requirements} requirements</span></div>
        ${externalAssessments(x.assessments)}</div>`)}` : ""}
    ${externals.length ? html`<h3 style="margin:14px 0 6px">Other frameworks (read-only)</h3>
      <div class="table-wrap"><table class="table compact"><thead><tr><th>Framework</th><th>Provider</th><th>Requirements</th><th>Assessments there</th><th>From</th></tr></thead><tbody>
      ${externals.map((x) => html`<tr class="clickable" data-act="go" data-href="${BASE}/${enc(x.id)}"><td><a href="${BASE}/${enc(x.id)}">${x.name}</a>
          ${x.caveat ? html` <span class="badge warn" title="${x.caveat}">${icon("alert")}source text</span>` : ""}</td>
        <td>${x.provider || "-"}</td><td>${x.counts.requirements}</td><td>${x.counts.assessments}</td>
        <td class="faint">${x.source.tool_name} ${timeAgo(x.source.pulled_at)}</td></tr>`)}</tbody></table></div>` : ""}`;
}

function catalogHead(fw) {
  return html`<div class="fw-req catalog ${fw.maps_to ? "maps" : ""} fw-head" aria-hidden="true"><span>Requirement</span><span>Levels</span><span>Suggested hub evidence</span>${fw.maps_to ? html`<span>Maps to CyFun 2025</span>` : ""}</div>`;
}

function catalogRow(r, fw) {
  const hub = fw.controls[r.ref_id] || [];
  const maps = fw.maps_to?.[r.ref_id] || [];
  return html`<div class="fw-req catalog ${fw.maps_to ? "maps" : ""}" data-row="${r.ref_id}">
    <div class="fw-ref"><button type="button" class="fw-link mono" data-act="req" data-ref="${r.ref_id}">${r.ref_id}</button>${measureBadges(r)}</div>
    <div>${levelChips(r)}</div>
    <div class="fw-hub">${hub.length ? hub.map((s) => html`<span class="badge ${({ pass: "ok", partial: "warn", fail: "bad" })[s.status] || ""}" title="${s.title}: ${s.status} (${s.fit_name} evidence)">${s.control}</span>`)
      : html`<span class="faint" style="font-size:12px">none</span>`}</div>
    ${fw.maps_to ? html`<div class="fw-hub">${maps.length ? maps.map((x) => html`<span class="badge" title="${x.relationship}">${x.ref_id}</span>`) : html`<span class="faint">-</span>`}</div>` : ""}</div>`;
}

/** A requirement of the catalog, without an assessment: tags, suggested hub controls, CyFun 2025 mapping. */
function openCatalogRequirement(fw, idx, ref) {
  const { r, fn, cat, sub } = idx[ref];
  const hub = fw.controls[ref] || [];
  const maps = fw.maps_to?.[ref] || [];
  modal({
    title: ref, wide: true, submit: null, cancel: "Close",
    body: html`<div class="row" style="gap:6px;margin-bottom:8px">${levelChips(r)}${measureBadges(r)}</div>
      <p style="margin-bottom:4px"><b>${sub.id}</b> ${sub.title}</p>
      <p class="faint" style="font-size:12px;margin-bottom:12px">${fn.id} ${fn.title} / ${cat.id} ${cat.title}. The CCB's requirement text is not included in Atrium:
        <a href="${r.text_url}" target="_blank" rel="noopener noreferrer">read ${ref} on cyfun.eu ${icon("external")}</a></p>
      <dl class="kv" style="margin-bottom:14px">
        <dt>Required at</dt><dd>${names(LEVELS.filter((l) => r.tags.includes(l)))}</dd>
        <dt>Key measure</dt><dd>${r.key_measure.length ? `at ${names(r.key_measure)}: must reach the level's key-measure threshold and may not be N/A` : "no"}</dd>
        ${fw.levels.some((l) => l.management_aspects) ? html`<dt>Management aspect</dt><dd>${r.management.length ? `at ${names(r.management)}` : "no"}</dd>` : ""}
        ${fw.maps_to ? html`<dt>CyFun 2025</dt><dd>${maps.length ? maps.map((x) => html`<code>${x.ref_id}</code> <span class="faint">${x.relationship}</span> `) : "no mapped requirement"}</dd>` : ""}
      </dl>
      <h3 style="margin-bottom:8px">Suggested hub controls</h3>${suggestedList(hub, [], false)}
      <p class="faint" style="font-size:12px;margin-top:8px">Score it in a self-assessment of ${fw.short_name}.</p>`,
  });
}

function openNewAssessment(fw) {
  const year = new Date().getFullYear();
  modal({
    title: `New ${fw.short_name} self-assessment`, wide: true, submit: "Start assessment", minRole: "operator",
    body: html`${fw.transition ? transitionNotice(fw.transition) : ""}
      ${field("Name", html`<input name="name" required maxlength="200" value="${fw.short_name} self-assessment ${year}">`)}
      <div class="field"><label>Target level</label><div class="fw-pick">${fw.levels.map((l, i) => html`<label class="radio-card"><input type="radio" name="target_level" value="${l.id}" ${i === 0 ? "checked" : ""}>
          <div><b>${l.name}</b><div class="faint" style="font-size:12px">${l.requirements} requirements, ${l.key_measures_count} key measures</div></div></label>`)}</div>
        <span class="hint">Levels are cumulative: Important includes every Basic requirement, Essential every Important one. You can change the target later.</span></div>
      ${field("Scope", html`<textarea name="scope" rows="2" maxlength="4000" placeholder="e.g. the whole organisation, or the production site"></textarea>`)}
      ${field("Notes", html`<textarea name="notes" rows="2" maxlength="8000"></textarea>`)}
      ${fw.assessments.length ? field("Start from", html`<select name="copy_from">${options([["", "An empty assessment"],
        ...fw.assessments.map((a) => [a.id, `The scores of "${a.name}" (${a.target_name}, ${a.progress.percent}% assessed)`])], "")}</select>`,
        "Copied scores keep their owners, notes, evidence links and age: the copy counts as last scored when the original was, until you review and change requirements.") : ""}`,
    async onSubmit(d) {
      const body = { name: String(d.get("name") || "").trim(), target_level: d.get("target_level") || "B",
        scope: String(d.get("scope") || "").trim(), notes: String(d.get("notes") || "").trim() };
      if (d.get("copy_from")) body.copy_from = d.get("copy_from");
      if (!body.name) throw new Error("Give the assessment a name");
      const created = await post(`/frameworks/${enc(fw.id)}/assessments`, body);
      toast(`Started "${created.name}"`, "ok");
      location.hash = `${BASE}/${enc(fw.id)}/${enc(created.id)}`;
    },
  });
}

async function renderEdition(el, ctx, fid, list) {
  let fw = await get(`/frameworks/${enc(fid)}`);
  if (!el.isConnected) return;
  const idx = indexOf(fw);
  const f = { level: "", key: false, mgmt: false, status: "", q: "" };
  const collapsed = new Set();
  const part = (n) => el.querySelector(`[data-part="${n}"]`);
  ctx.crumb(`Compliance hub / ${fw.short_name}`);

  setHTML(el, html`${editionBar(list, fid)}
    ${transitionNotice(fw.transition)}
    <section class="card flush" style="margin-bottom:16px" data-part="assessments"></section>
    <div class="grid split">
      <section class="card"><header><h2>Catalog</h2><a href="${fw.text_url}" target="_blank" rel="noopener noreferrer" style="font-size:13px">Requirement text on cyfun.eu ${icon("external")}</a></header>
        <p class="faint" style="font-size:12.5px;margin-bottom:10px">Function, category and subcategory from ${fw.based_on}; requirement ids and level tags from CyFun.
          Key measures must reach their threshold at a level; hub controls mapped to a requirement are suggested as evidence.</p>
        ${filterBar(fw, f, CATALOG_FILTERS)}<div data-part="tree"></div></section>
      <section class="stack" style="align-self:start"><div class="card" data-part="about"></div><div class="card" data-part="sync"></div></section></div>`);

  const drawTree = () => {
    let shown = 0;
    const keep = (r) => {
      const ok = baseMatch(r, f, idx) && (!f.status || HUB_TESTS[f.status](fw.controls[r.ref_id] || []));
      if (ok) shown++;
      return ok;
    };
    const body = treeView(fw, keep, { collapsed, row: (r) => catalogRow(r, fw) });
    setHTML(part("tree"), shown ? html`${catalogHead(fw)}<div class="fw-tree">${body}</div>` : emptyState("search", "No requirement matches", "Change the filters to see others."));
    part("count").textContent = `${shown} of ${fw.counts.requirements} requirements`;
  };
  const draw = () => {
    setHTML(part("assessments"), assessmentsCard(fw, list));
    setHTML(part("about"), aboutCard(fw));
    setHTML(part("sync"), syncCard(list, fw));
    drawTree();
  };
  bindTree(el, f, collapsed, drawTree);
  actions(el, {
    go: (d) => { location.hash = d.href; },
    new: () => openNewAssessment(fw),
    req: (d) => openCatalogRequirement(fw, idx, d.ref),
  });
  draw();
  const refresh = async () => {
    if (!el.isConnected) return;
    const [l, d] = await Promise.all([get("/frameworks"), get(`/frameworks/${enc(fid)}`)]);
    if (!el.isConnected) return;
    [list, fw] = [l, d];
    draw();
  };
  ctx.live(["framework_assessment", "framework_assessment_removed", "external_framework", "external_framework_removed", "grc", "flow", "flow_removed", "connection"],
    () => refresh().catch(() => {}), 700);
}

// ---------- assessment workspace ----------

function suggestedList(list, items, writable) {
  if (!list.length) return html`<p class="faint" style="font-size:12.5px">No hub control is mapped to this requirement. Link a policy, a document or a URL as evidence.</p>`;
  return html`${list.map((s) => {
    const linked = items.some((e) => e.kind === "control" && e.ref === s.control);
    return html`<div class="fw-ev-item"><div class="fw-ico ico ${s.status}">${icon(STATUS_ICON[s.status] || "minus")}</div>
      <div style="flex:1;min-width:0"><div class="row" style="gap:6px"><code>${s.control}</code><b>${s.title}</b>${statusBadge(s.status)}
        <span class="badge" title="How well the control evidences this requirement (analyst judgement, not CCB guidance)">${s.fit_name} evidence</span></div>
        ${s.detail ? html`<div class="faint" style="font-size:12px">${s.detail}</div>` : ""}</div>
      ${writable ? (linked ? html`<span class="faint" style="font-size:12px">linked</span>`
        : html`<button type="button" class="btn sm" data-act="ev-link" data-control="${s.control}">${icon("link")}Link</button>`) : ""}</div>`;
  })}<p class="faint" style="font-size:12px">Suggestions only: a control's result is evidence, never a score. The mapping is analyst judgement, not CCB guidance.</p>`;
}

function evidenceItem(e, i, writable) {
  const href = e.kind === "url" ? safeHref(e.ref) : null;
  const label = e.title || e.display || e.ref;
  const what = e.kind === "control" ? html`<code>${e.ref}</code> ${label === e.ref ? "" : label}`
    : href ? html`<a href="${href}" target="_blank" rel="noopener noreferrer">${label}</a>` : label;
  const state = e.kind === "control" && e.status ? statusBadge(e.status)
    : e.kind === "policy" && e.found ? html`${badge(e.status)}<span class="faint">v${e.version}</span>`
      : e.kind === "risk" && e.found ? html`${badge(e.status)}<span class="faint">score ${e.score}</span>` : "";
  return html`<div class="fw-ev-item">${icon(EVIDENCE_ICON[e.kind] || "link")}
    <div style="flex:1;min-width:0"><div class="row" style="gap:6px"><span style="overflow-wrap:anywhere">${what}</span>${state}
        ${e.found === false ? badge("no longer exists", "bad") : ""}${e.added_at ? "" : badge("new - save to keep", "info")}</div>
      ${e.kind === "control" && e.detail ? html`<div class="faint" style="font-size:12px">${e.detail}</div>` : ""}
      ${(e.kind === "url" || e.kind === "file") && label !== e.ref ? html`<div class="faint mono" style="font-size:11.5px;overflow-wrap:anywhere">${e.ref}</div>` : ""}
      ${e.added_at ? html`<div class="faint" style="font-size:11.5px">added ${timeAgo(e.added_at)} by ${e.added_by}</div>` : ""}</div>
    ${writable ? html`<button type="button" class="icon-btn sm danger" data-act="ev-remove" data-i="${i}" aria-label="Remove ${label}" title="Remove">${icon("x")}</button>` : ""}</div>`;
}

function historyList(history, nameOf) {
  const show = (k, v) => (v === null || v === undefined || v === "" || (Array.isArray(v) && !v.length) ? "-"
    : Array.isArray(v) ? v.join(", ") : typeof v === "boolean" ? (v ? "yes" : "no") : k === "owner_person_id" ? nameOf(v) : String(v));
  return html`<ul class="fw-history">${history.slice().reverse().map((h) => html`<li><span class="faint">${dateTime(h.at)} - ${h.by}</span>
    ${Object.entries(h.changes).map(([k, [a, b]]) => html`<div>${HISTORY_LABELS[k] || k}: ${show(k, a)} &rarr; ${show(k, b)}</div>`)}</li>`)}</ul>`;
}

function ruleRow(rule) {
  const state = rule.ok ? "pass" : rule.missing_only ? "manual" : "fail";
  const scored = rule.value != null && rule.value >= 0;
  const value = rule.id === "maturity" ? (scored ? `${fmt(rule.value)} / ${fmt(rule.threshold)}` : `needs ${fmt(rule.threshold)}`)
    : rule.id === "key_measures" ? (scored ? `lowest ${fmt(rule.value)} / ${fmt(rule.threshold)}` : `each needs ${fmt(rule.threshold)}`)
      : rule.id === "exclusions" ? `${rule.value} N/A / at most ${rule.threshold}`
        : rule.id === "categories" ? `each at least ${fmt(rule.threshold)}` : "";
  return html`<div class="fw-rule"><div class="fw-ico ico ${state}">${icon(rule.ok ? "check" : rule.missing_only ? "minus" : "x")}</div>
    <div style="min-width:0"><div>${rule.label} <span class="faint">${value}</span><span class="sr-only">${rule.ok ? " holds" : rule.missing_only ? " not scored yet" : " fails"}</span></div>
      ${rule.reasons.map((r) => html`<div class="faint fw-reason">${r}</div>`)}</div></div>`;
}

function levelCard(lv, fw, target) {
  const rules = fw.conformity.levels[lv.level];
  const p = lv.progress;
  const extra = lv.reasons.filter((r) => !lv.rules.some((x) => x.reasons.includes(r)));
  return html`<section class="card fw-level ${lv.level === target ? "target" : ""} ${lv.targeted ? "" : "beyond"}">
    <header><h3>${lv.name}</h3>${lv.level === target ? badge("target", "accent") : lv.targeted ? badge("included") : html`<span class="faint" style="font-size:12px">beyond target</span>`}
      <span class="spacer"></span>${verdictBadge(lv.verdict)}</header>
    <div class="row" style="gap:10px;margin-bottom:6px"><span class="fw-big">${fmt(lv.groups[lv.level].maturity)}</span>${meter(lv.groups[lv.level].maturity, rules.maturity_min, `${lv.name} maturity`)}
      <span class="faint" style="font-size:12px">needs ${fmt(rules.maturity_min)}</span></div>
    <div class="progress" style="margin-bottom:4px"><span style="width:${p.percent}%"></span></div>
    <div class="faint" style="font-size:12px;margin-bottom:8px">${p.scored} scored, ${p.na} N/A, ${p.unscored} not scored of ${p.total}</div>
    ${lv.rules.map(ruleRow)}
    ${extra.map((r) => html`<div class="faint fw-reason" style="margin-top:4px">${r}</div>`)}</section>`;
}

function scoreCells(s, target) {
  return html`<td><span class="fw-score">${meter(s.maturity, target)}<b>${fmt(s.maturity)}</b></span></td><td>${fmt(s.implementation)}</td><td>${fmt(s.documentation)}</td>
    <td>${s.scored}/${s.total}</td><td>${s.na}</td>`;
}

function scoresView(detail, fw) {
  const ev = detail.evaluation;
  const target = fw.conformity.group_targets[detail.target_level];
  const groups = ev.levels.flatMap((lv) => Object.entries(lv.groups).filter(([, g]) => g.total).map(([id, g]) => ({ id, g, lv })));
  return html`<div class="grid split">
    <section class="card flush"><header><h2>Functions and categories</h2><span class="faint" style="font-size:12px">${detail.target_name} requirements, target ${fmt(target)}</span></header>
      <div class="table-wrap" style="margin-top:8px"><table class="table compact"><thead><tr><th>Function / category</th><th>Maturity</th><th>Impl.</th><th>Doc.</th><th>Assessed</th><th>N/A</th></tr></thead><tbody>
      ${ev.functions.map((fn) => html`<tr><td><b>${fn.id} ${fn.title}</b></td>${scoreCells(fn, target)}</tr>
        ${ev.categories.filter((c) => c.function === fn.id).map((c) => html`<tr><td style="padding-left:22px"><code>${c.id}</code> ${c.title} ${c.below ? badge("below target", "warn") : ""}</td>${scoreCells(c, c.target)}</tr>`)}`)}
      </tbody></table></div></section>
    <section class="card flush"><header><h2>Groups</h2><span class="faint" style="font-size:12px">as the conformity rules read them</span></header>
      <div class="table-wrap" style="margin-top:8px"><table class="table compact"><thead><tr><th>Group</th><th>Maturity</th><th>Lowest</th><th>Assessed</th><th>N/A</th></tr></thead><tbody>
      ${groups.map(({ id, g, lv }) => html`<tr class="${lv.targeted ? "" : "stale"}"><td>${LEVEL_NAMES[id[0]]} ${GROUP_NAMES[id.slice(1)]} <span class="faint">${id}</span></td>
        <td><span class="fw-score">${meter(g.maturity, fw.conformity.group_targets[id])}<b>${fmt(g.maturity)}</b></span></td><td>${fmt(g.min_maturity)}</td><td>${g.scored}/${g.total}</td><td>${g.na}</td></tr>`)}
      </tbody></table></div>
      <p class="faint" style="font-size:12px;padding:0 16px 14px">Targets: ${Object.entries(fw.conformity.group_targets).map(([k, v]) => `${k} ${fmt(v)}`).join(", ")}. "Lowest" counts a requirement not scored yet as missing.</p></section></div>`;
}

const refButton = (ref) => html`<button type="button" class="fw-link mono" data-act="req" data-ref="${ref}">${ref}</button>`;

function gapsView(detail) {
  const ev = detail.evaluation;
  const keys = ev.key_measures;
  const keyState = (k) => (k.na ? badge("N/A - not allowed", "bad") : k.maturity == null ? badge("not scored") : k.ok ? badge("ok", "ok") : badge("below", "warn"));
  return html`<div class="grid split">
    <section class="card flush"><header><h2>Below target (${ev.gaps.length})</h2><span class="faint" style="font-size:12px">${detail.target_name} requirements, key measures first</span></header>
      ${ev.gaps.length ? html`<div class="table-wrap" style="margin-top:8px"><table class="table compact"><thead><tr><th>Requirement</th><th>Maturity</th><th>Target</th><th></th></tr></thead><tbody>
        ${ev.gaps.map((g) => html`<tr><td>${refButton(g.ref_id)}<div class="faint" style="font-size:12px">${g.title}</div></td>
          <td><span class="fw-score">${meter(g.maturity, g.target)}<b>${fmt(g.maturity)}</b></span></td><td>${fmt(g.target)}</td><td>${g.key_measure ? badge("key measure", "warn") : ""}</td></tr>`)}
        </tbody></table></div>`
      : html`<div style="padding:0 16px 8px">${emptyState("checkCircle", "No gaps among the scored requirements", ev.unscored.length ? `${ev.unscored.length} requirements are not scored yet.` : "Every requirement reaches its target.")}</div>`}</section>
    <section class="stack">
      <div class="card flush"><header><h2>Key measures</h2><span class="faint" style="font-size:12px">${keys.filter((k) => k.ok).length} of ${keys.length} at ${detail.target_name} reach their threshold</span></header>
        ${keys.length ? html`<div class="table-wrap" style="margin-top:8px"><table class="table compact"><thead><tr><th>Requirement</th><th>Maturity</th><th>Threshold</th><th></th></tr></thead><tbody>
          ${keys.map((k) => html`<tr><td>${refButton(k.ref_id)}</td><td>${k.na ? "N/A" : fmt(k.maturity)}</td><td>${fmt(k.threshold)}</td><td>${keyState(k)}</td></tr>`)}</tbody></table></div>`
        : html`<p class="muted" style="padding:0 16px 14px">No key measures at this level.</p>`}</div>
      <div class="card"><header><h3>Not scored yet (${ev.unscored.length})</h3>${ev.unscored.length ? html`<button type="button" class="btn sm" data-act="show-status" data-status="unscored">Show them</button>` : ""}</header>
        <p class="faint" style="font-size:12.5px">Left out of the averages; a key measure not scored fails its rule.</p></div>
      <div class="card"><header><h3>Documentation maturity missing (${ev.documentation_missing.length})</h3>${ev.documentation_missing.length ? html`<button type="button" class="btn sm" data-act="show-status" data-status="nodoc">Show them</button>` : ""}</header>
        <p class="faint" style="font-size:12.5px">An implementation maturity without a documentation maturity counts the documentation as 1.</p>
        ${ev.documentation_missing.length ? html`<div class="row" style="gap:6px;margin-top:6px">${ev.documentation_missing.slice(0, 40).map(refButton)}</div>` : ""}</div>
    </section></div>`;
}

function detailsView(detail, fw, list) {
  const m = detail.evaluation.method;
  const sync = list.sync.map((c) => ({ c, link: c.assessments[detail.id] }));
  return html`<div class="grid split">
    <section class="stack">
      <div class="card"><header><h2>Assessment</h2></header><dl class="kv">
        <dt>Framework</dt><dd>${fw.name}</dd><dt>Target level</dt><dd>${detail.target_name}</dd><dt>Status</dt><dd>${badge(detail.status)}</dd>
        <dt>Started</dt><dd>${dateTime(detail.created_at)} by ${detail.created_by}</dd>
        <dt>Last change</dt><dd>${dateTime(detail.updated_at)} by ${detail.updated_by}</dd>
        <dt>Last scored</dt><dd>${detail.assessed_at ? dateTime(detail.assessed_at) : "not yet"}${detail.stale ? html` ${badge("older than 12 months", "warn")}` : ""}</dd>
        ${detail.completed_at ? html`<dt>Completed</dt><dd>${dateTime(detail.completed_at)}</dd>` : ""}</dl>
        <h3 style="margin:14px 0 6px">Scope</h3><div class="prose-box">${detail.scope || "Not described."}</div>
        <h3 style="margin:14px 0 6px">Notes</h3><div class="prose-box">${detail.notes || "None."}</div></div>
      <div class="card"><header><h2>CISO Assistant</h2></header>
        ${sync.length ? sync.map(({ c, link }) => html`<p style="font-size:13px;margin-bottom:6px">${c.tool_name}: ${link ? html`sent ${timeAgo(link.synced_at)} as compliance assessment <code>${link.external_id}</code>`
          : c.push_enabled ? (detail.status === "archived" ? "archived assessments are not sent" : "sent at its next push run") : "sending self-assessments is off (an administrator can allow it in the connection)"}</p>`)
        : html`<p class="muted" style="font-size:13px">No CISO Assistant connection.</p>`}</div></section>
    <section class="stack">
      <div class="card"><header><h2>Scoring method</h2></header>
        ${sourceNote(m.source.replace(/\.$/, ""), m.verified_against_library)}
        <dl class="kv" style="margin-top:12px"><dt>N/A counts as</dt><dd>${fmt(m.na_counts_as)}</dd><dt>Documentation not scored</dt><dd>counts as ${m.missing_documentation_counts_as}</dd>
          <dt>Calculation</dt><dd>${m.calculation}</dd></dl>
        <h3 style="margin:14px 0 6px">Thresholds</h3>${thresholdsTable(fw)}</div>
      <div class="card"><header><h2>Maturity scale</h2></header>${scaleTable(detail.scale)}</div></section></div>`;
}

function scaleTable(scale) {
  return html`<div class="table-wrap"><table class="table compact"><thead><tr><th>Score</th><th>Implementation</th><th>Documentation</th></tr></thead><tbody>
    ${scale.map((s) => html`<tr><td><b>${s.score}</b> ${s.name}</td><td>${s.implementation}</td><td>${s.documentation}</td></tr>`)}</tbody></table></div>
    <p class="faint" style="font-size:12px;margin-top:6px">Scale names from CyFun 2025; the one-line descriptions are Atrium's wording, not the CCB's.</p>`;
}

async function downloadPack(fid, aid, btn) {
  btn.disabled = true;
  try {
    const res = await fetch(`/api/frameworks/${enc(fid)}/assessments/${enc(aid)}/audit-pack`);
    if (res.status === 401) window.dispatchEvent(new CustomEvent("atrium:signed-out"));
    if (!res.ok) {
      const data = await res.json().catch(() => null);
      throw new Error(typeof data?.detail === "string" ? data.detail : `${res.status} ${res.statusText}`);
    }
    const name = /filename="([^"]+)"/.exec(res.headers.get("Content-Disposition") || "")?.[1] || "audit-pack.zip";
    const url = URL.createObjectURL(await res.blob());
    const a = Object.assign(document.createElement("a"), { href: url, download: name });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
    toast(`Audit pack ${name} downloaded`, "ok");
  } catch (err) {
    toast(err.message, "bad");
  } finally {
    btn.disabled = false;
  }
}

async function renderWorkspace(el, ctx, fid, aid, viewParam, list) {
  const api = `/frameworks/${enc(fid)}/assessments/${enc(aid)}`;
  let fw, detail, people;
  try {
    [fw, detail, people] = await Promise.all([get(`/frameworks/${enc(fid)}`), get(api), loadPeople()]);
  } catch (err) {
    if (err.status !== 404) throw err;
    ctx.crumb("Compliance hub / assessment not found");
    setHTML(el, notFound("Assessment not found", "It may have been deleted."));
    return;
  }
  if (!el.isConnected) return;
  const idx = indexOf(fw);
  let view = VIEWS.some(([k]) => k === viewParam) ? viewParam : "requirements";
  const f = { level: detail.target_level, key: false, mgmt: false, status: "", q: "" };
  const collapsed = new Set();
  const pinned = new Set(); // rows changed since the filters last changed stay visible (no row vanishes mid-scoring)
  let byId = Object.fromEntries(people.map((p) => [p.id, p]));
  const part = (n) => el.querySelector(`[data-part="${n}"]`);
  const editable = () => can("operator") && detail.status !== "archived";
  const goalOf = (r) => (r.key_measure.includes(detail.target_level) ? fw.conformity.levels[detail.target_level].key_measure_min
    : fw.conformity.group_targets[r.tags.includes(detail.target_level) ? detail.target_level : r.level]);
  const nameOf = (id) => byId[id]?.display_name || (detail.requirements && Object.values(detail.requirements).find((e) => e.owner?.id === id)?.owner?.display_name) || id;

  setHTML(el, html`<nav class="fw-crumbs" aria-label="Breadcrumb"><a href="${BASE}">Frameworks</a> / <a href="${BASE}/${enc(fid)}">${fw.short_name}</a> / <span>self-assessment</span></nav>
    <div data-part="head"></div><div data-part="notices"></div><div data-part="summary"></div>
    <div class="grid fw-levels" data-part="levels"></div><div data-part="views" style="margin:16px 0 12px"></div><div data-part="view"></div>`);

  // ---------- parts ----------
  const drawHead = () => {
    ctx.crumb(`Compliance hub / ${fw.short_name} / ${detail.name}`);
    const statusButtons = detail.status === "in_progress"
      ? html`<button type="button" class="btn sm ok" data-act="status" data-status="completed">${icon("check")}Mark completed</button>`
      : html`<button type="button" class="btn sm" data-act="status" data-status="in_progress">${icon("undo")}Reopen</button>
        ${detail.status === "completed" ? html`<button type="button" class="btn sm" data-act="status" data-status="archived">${icon("box")}Archive</button>` : ""}`;
    const sent = list.sync.find((c) => c.assessments[detail.id]);
    setHTML(part("head"), html`<div class="fw-title"><div style="min-width:0"><h2 class="fw-name">${detail.name}</h2>
        <div class="row" style="gap:6px;margin-top:6px">${badge(fw.short_name, "accent")}<span class="badge">target ${detail.target_name}</span>${badge(detail.status)}
          ${detail.stale ? badge("older than 12 months", "warn") : ""}
          <span class="faint" style="font-size:12px">updated ${timeAgo(detail.updated_at)} by ${detail.updated_by}</span>
          ${sent ? html`<span class="faint row" style="gap:4px;font-size:12px">${icon("check")}sent to ${sent.tool_name} ${timeAgo(sent.assessments[detail.id].synced_at)}</span>` : ""}</div></div>
      <div class="row" style="gap:6px"><span class="row" style="gap:6px" data-min-role="operator">${statusButtons}
          <button type="button" class="btn sm" data-act="edit">${icon("edit")}Edit</button></span>
        <button type="button" class="btn sm" data-act="pack" title="ZIP: printable summary, requirements CSV, evidence index, assessment JSON and a manifest with SHA-256 hashes">${icon("download")}Audit pack</button>
        <button type="button" class="btn sm danger" data-act="delete" data-min-role="admin">${icon("trash")}Delete</button></div></div>`);
  };

  const drawNotices = () => {
    const p = detail.evaluation.progress;
    setHTML(part("notices"), html`${detail.status === "archived" ? html`<div class="notice warn" style="margin-bottom:14px">${icon("lock")}<div><b>Archived.</b>
        <span class="muted">Scores are read-only and the assessment is no longer sent to CISO Assistant. Reopen it to change scores.</span></div></div>` : ""}
      ${transitionNotice(detail.transition)}
      ${detail.stale ? html`<div class="notice warn" style="margin-bottom:14px">${icon("clock")}<div><b>Last scored more than 12 months ago.</b>
        <span class="muted">Control HB-PO-3 (self-assessment is current) reports it as out of date until requirements are reviewed again.</span></div></div>` : ""}
      ${p.documentation_missing ? html`<div class="notice" style="margin-bottom:14px">${icon("file")}<div>${p.documentation_missing} requirement${p.documentation_missing === 1 ? " has" : "s have"}
        an implementation maturity but no documentation maturity: it counts as 1. <button type="button" class="fw-link" data-act="show-status" data-status="nodoc">Show them</button></div></div>` : ""}`);
  };

  const drawSummary = () => {
    const ev = detail.evaluation;
    const p = ev.progress;
    const rules = fw.conformity.levels[detail.target_level];
    const keysOk = ev.key_measures.filter((k) => k.ok).length;
    const firstReason = ev.levels.find((l) => l.level === detail.target_level)?.reasons[0];
    setHTML(part("summary"), html`<div class="grid cols-5" style="margin-bottom:16px">
      <div class="card"><div class="fw-tile-label">Assessed (${detail.target_name})</div><div class="fw-tile-value">${p.percent}%</div>
        <div class="progress" style="margin:6px 0"><span style="width:${p.percent}%"></span></div>
        <div class="faint" style="font-size:12px">${p.scored} scored, ${p.na} N/A, ${p.unscored} to go of ${p.total}</div></div>
      <div class="card"><div class="fw-tile-label">Maturity</div><div class="fw-tile-value">${fmt(ev.overall.maturity)}</div>${meter(ev.overall.maturity, rules.maturity_min)}
        <div class="faint" style="font-size:12px;margin-top:4px">implementation ${fmt(ev.overall.implementation)}, documentation ${fmt(ev.overall.documentation)}; needs ${fmt(rules.maturity_min)}</div></div>
      <div class="card"><div class="fw-tile-label">${detail.target_name} level</div><div class="fw-tile-value">${verdictBadge(ev.verdict)}</div>
        <div class="faint fw-clamp" style="font-size:12px" title="${firstReason || ""}">${ev.verdict === "met" ? "Every rule holds and every requirement is assessed." : firstReason || ""}</div></div>
      <div class="card"><div class="fw-tile-label">Key measures</div><div class="fw-tile-value">${keysOk}/${ev.key_measures.length}</div>
        <div class="faint" style="font-size:12px">at least ${fmt(rules.key_measure_min)} and none N/A</div></div>
      <div class="card"><div class="fw-tile-label">Gaps</div><div class="fw-tile-value">${ev.gaps.length}</div>
        <div class="faint" style="font-size:12px">scored requirements below their target</div></div></div>`);
  };

  const drawLevels = () => {
    setHTML(part("levels"), detail.evaluation.levels.map((lv) => levelCard(lv, fw, detail.target_level)));
  };

  const drawViews = () => {
    const counts = { gaps: detail.evaluation.gaps.length };
    setHTML(part("views"), html`<div class="seg" aria-label="View">${VIEWS.map(([k, label]) => html`<button type="button" class="${view === k ? "active" : ""}" aria-pressed="${String(view === k)}"
      data-act="view" data-view="${k}">${label}${counts[k] ? html` <span class="badge warn">${counts[k]}</span>` : ""}</button>`)}</div>`);
  };

  const workHead = () => html`<div class="fw-req fw-head" aria-hidden="true"><span>Requirement</span><span>Levels</span><span>Implementation</span><span>Documentation</span><span>Maturity</span><span>Owner</span><span>Evidence</span></div>`;

  const scoreCell = (r, e, dim, writable) => {
    const v = e[dim];
    const label = `${dim === "implementation" ? "Implementation" : "Documentation"} maturity of ${r.ref_id}`;
    const short = dim === "implementation" ? "Impl." : "Doc.";
    if (!writable) return html`<span title="${label}"><span class="fw-lbl">${short} </span>${v ? html`${v} <span class="faint">${detail.scale.find((s) => s.score === v)?.name}</span>` : html`<span class="faint">-</span>`}</span>`;
    return html`<label class="fw-sel"><span class="fw-lbl">${short}</span><select data-score="${dim}" data-ref="${r.ref_id}" aria-label="${label}" data-min-role="operator"
      title="${e.na ? "N/A: the scores are kept but not counted" : label}">${options([["", "-"], ...detail.scale.map((s) => [String(s.score), `${s.score} ${s.name}`])], v ? String(v) : "")}</select></label>`;
  };

  const workRow = (r, gaps, writable) => {
    const e = detail.requirements[r.ref_id];
    const inScope = r.tags.includes(detail.target_level);
    const owner = byId[e.owner_person_id] || e.owner;
    return html`<div class="fw-req ${inScope ? "" : "out"}" data-row="${r.ref_id}" title="${inScope ? "" : `Not required at ${detail.target_name}`}">
      <div class="fw-ref">${refButton(r.ref_id)}${measureBadges(r)}</div>
      <div>${levelChips(r)}</div>
      <div>${scoreCell(r, e, "implementation", writable)}</div>
      <div>${scoreCell(r, e, "documentation", writable)}</div>
      <div>${e.na ? html`<span class="badge" title="Not applicable: ${e.na_justification}">N/A</span> <span class="faint" style="font-size:12px">as ${fmt(fw.conformity.na_counts_as)}</span>`
        : html`<span class="fw-score">${meter(e.maturity, goalOf(r))}<b class="${gaps.has(r.ref_id) ? "warn-text" : ""}">${fmt(e.maturity)}</b></span>`}</div>
      <div class="fw-owner">${owner ? personChip(owner) : e.owner_person_id ? html`<span class="faint">removed person</span>` : html`<span class="faint">-</span>`}</div>
      <div><span class="fw-score" title="${e.evidence.length} evidence link(s); ${e.suggested.length} suggested hub control(s)">${icon("link")}${e.evidence.length}
        ${e.suggested.length ? html`<span class="fw-dots">${e.suggested.map((s) => html`<span class="dot ${({ pass: "ok", partial: "warn", fail: "bad" })[s.status] || ""}"></span>`)}</span>` : ""}</span></div></div>`;
  };

  const drawTree = () => {
    const box = part("tree");
    if (!box) return;
    const gaps = new Set(detail.evaluation.gaps.map((g) => g.ref_id));
    const writable = editable();
    let shown = 0;
    const keep = (r) => {
      const ok = pinned.has(r.ref_id) || (baseMatch(r, f, idx) && (!f.status || WORK_TESTS[f.status](detail.requirements[r.ref_id], gaps)));
      if (ok) shown++;
      return ok;
    };
    const fns = Object.fromEntries(detail.evaluation.functions.map((x) => [x.id, x]));
    const cats = Object.fromEntries(detail.evaluation.categories.map((x) => [x.id, x]));
    const target = fw.conformity.group_targets[detail.target_level];
    const chip = (s) => html`<span class="fw-score">${meter(s.maturity, target)}<b>${fmt(s.maturity)}</b><span class="faint">${s.scored}/${s.total}</span></span>`;
    const body = treeView(fw, keep, {
      collapsed, row: (r) => workRow(r, gaps, writable),
      fnScore: (id) => (fns[id] ? chip(fns[id]) : ""),
      catScore: (id) => (cats[id] ? html`${cats[id].below ? badge(`below ${fmt(cats[id].target)}`, "warn") : ""}${chip(cats[id])}` : ""),
    });
    setHTML(box, shown ? html`${workHead()}<div class="fw-tree">${body}</div>` : emptyState("search", "No requirement matches", "Change the filters to see others."));
    const count = part("count");
    if (count) count.textContent = `${shown} of ${fw.counts.requirements} requirements`;
  };

  const drawView = () => {
    if (view === "requirements") {
      setHTML(part("view"), html`<section class="card"><p class="faint" style="font-size:12.5px;margin-bottom:10px">Score each requirement on <b>implementation</b> and
          <b>documentation</b> maturity, 1 Initial to 5 Optimizing. Open a requirement for N/A, owner, notes and evidence; its text is on
          <a href="${detail.text_url}" target="_blank" rel="noopener noreferrer">cyfun.eu</a>.</p>
        <details style="margin-bottom:10px"><summary class="faint" style="cursor:pointer;font-size:12.5px">What the scores mean</summary><div style="margin-top:8px">${scaleTable(detail.scale)}</div></details>
        ${filterBar(fw, f, WORK_FILTERS)}<div data-part="tree"></div></section>`);
      drawTree();
    } else {
      setHTML(part("view"), view === "scores" ? scoresView(detail, fw) : view === "gaps" ? gapsView(detail) : detailsView(detail, fw, list));
    }
  };

  /** Everything but the filter inputs, keeping the focused control. */
  const redraw = (focus = focusKey(el)) => {
    drawHead();
    drawNotices();
    drawSummary();
    drawLevels();
    drawViews();
    if (view === "requirements") drawTree(); else drawView();
    if (focus) el.querySelector(focus)?.focus();
  };

  const apply = (res) => {
    detail.requirements[res.requirement.ref_id] = res.requirement;
    Object.assign(detail, res.assessment, { evaluation: res.evaluation });
  };

  const setView = (next) => {
    view = next;
    history.replaceState(null, "", `${BASE}/${enc(fid)}/${enc(aid)}${view === "requirements" ? "" : `/${view}`}`);
    drawViews();
    drawView();
  };

  // ---------- the requirement editor ----------
  const openRequirement = async (ref) => {
    const { r, fn, cat, sub } = idx[ref];
    const entry = detail.requirements[ref];
    const writable = editable();
    let pick = { controls: [], policies: [], risks: [] };
    if (writable) {
      const [grc, policies, risks] = await Promise.all([get("/grc"), get("/grc/policies"), get("/grc/risks")]).catch(() => [{ controls: [] }, [], []]);
      pick = { controls: grc.controls, policies, risks };
    }
    const items = entry.evidence.map((e) => ({ ...e }));
    const target = detail.target_level;
    const limits = fw.conformity.levels[target];
    const mgmt = fw.levels.some((l) => l.management_aspects);
    const goal = goalOf(r);
    const scaleOptions = (v) => options([["", "- not scored"], ...detail.scale.map((s) => [String(s.score), `${s.score} ${s.name}`])], v ? String(v) : "");
    const body = html`<div class="row" style="gap:6px;margin-bottom:8px">${levelChips(r)}${measureBadges(r)}
        ${r.tags.includes(target) ? badge(`required at ${LEVEL_NAMES[target]}`, "accent") : badge(`not required at ${LEVEL_NAMES[target]}`)}</div>
      <p style="margin-bottom:4px"><b>${sub.id}</b> ${sub.title}</p>
      <p class="faint" style="font-size:12px;margin-bottom:12px">${fn.id} ${fn.title} / ${cat.id} ${cat.title}. The CCB's requirement text is not included in Atrium:
        <a href="${detail.text_url}" target="_blank" rel="noopener noreferrer">read ${ref} on cyfun.eu ${icon("external")}</a></p>
      <div class="form-grid">
        ${field("Implementation maturity", html`<select name="implementation">${scaleOptions(entry.implementation)}</select>`, html`<span data-hint="implementation"></span>`)}
        ${field("Documentation maturity", html`<select name="documentation">${scaleOptions(entry.documentation)}</select>`, html`<span data-hint="documentation"></span>`)}</div>
      <p class="faint" style="font-size:12.5px;margin:-4px 0 12px" data-preview aria-live="polite"></p>
      <label class="check" style="margin-bottom:10px"><input type="checkbox" name="na" ${entry.na ? "checked" : ""}> Not applicable</label>
      <div data-na-box ${entry.na ? "" : "hidden"}>${field("Why it does not apply", html`<textarea name="na_justification" rows="2" maxlength="2000">${entry.na_justification}</textarea>`,
        `Required. N/A counts as ${fmt(fw.conformity.na_counts_as)} in the averages. At ${LEVEL_NAMES[target]} at most ${limits.na_max} requirement${limits.na_max === 1 ? "" : "s"} may be N/A, and no key measure${mgmt && limits.na_max_management === 0 ? " or management aspect" : ""}.`)}</div>
      <div class="form-grid">${field("Owner", html`<select name="owner_person_id">${personOptions(people, entry.owner_person_id, { none: "No owner" })}</select>`,
        people.length ? "The accountable person (People app)." : "No people yet - add them in the People app.")}</div>
      ${field("Notes", html`<textarea name="notes" rows="3" maxlength="8000" placeholder="How it is done here, who checked it, open points">${entry.notes}</textarea>`)}
      <h3 style="margin:6px 0 8px">Evidence</h3><div data-part="ev-list"></div>
      ${writable ? html`<div class="fw-ev-add" data-min-role="operator"><select name="ev_kind" aria-label="Kind of evidence">${options(EVIDENCE_KINDS, "control")}</select>
        <span data-part="ev-ref"></span><input name="ev_title" maxlength="300" placeholder="Title (optional)" aria-label="Evidence title">
        <button type="button" class="btn sm" data-act="ev-add">${icon("plus")}Add</button></div>` : ""}
      <h3 style="margin:16px 0 8px">Suggested hub controls</h3><div data-part="ev-suggested"></div>
      ${entry.history.length ? html`<details style="margin-top:14px"><summary class="faint" style="cursor:pointer">History (${entry.history.length})</summary>${historyList(entry.history, nameOf)}</details>` : ""}
      ${entry.updated_at ? html`<p class="faint" style="font-size:12px;margin-top:8px">Last changed ${timeAgo(entry.updated_at)} by ${entry.updated_by}</p>` : ""}`;
    const m = modal({
      title: `${ref} ${r.key_measure.includes(target) ? "(key measure)" : ""}`, wide: true, minRole: "operator",
      submit: writable ? "Save" : null, cancel: writable ? "Cancel" : "Close",
      body: writable || !can("operator") ? body : html`<fieldset class="plain" disabled>${body}</fieldset>`,
      async onSubmit(d, form) {
        const q = (n) => form.querySelector(`[name="${n}"]`);
        const num = (v) => (v ? Number(v) : null);
        const patchBody = {
          implementation: num(q("implementation").value), documentation: num(q("documentation").value), na: q("na").checked,
          na_justification: q("na_justification").value.trim(), owner_person_id: q("owner_person_id").value || null, notes: q("notes").value,
          evidence: items.map((e) => ({ kind: e.kind, ref: e.ref, title: (e.title || "").slice(0, 300) })),
        };
        if (patchBody.na && patchBody.na_justification.length < 3) {
          q("na_justification").focus();
          throw new Error("Say why the requirement does not apply (at least 3 characters)");
        }
        const res = await patch(`${api}/requirements/${enc(ref)}`, patchBody);
        apply(res);
        pinned.add(ref);
        redraw(null);
        toast(`${ref} saved`, "ok");
      },
    });
    const q = (n) => m.el.querySelector(`[name="${n}"]`);
    const drawEvidence = () => {
      setHTML(m.el.querySelector('[data-part="ev-list"]'), items.length ? items.map((e, i) => evidenceItem(e, i, writable))
        : html`<p class="faint" style="font-size:12.5px;margin-bottom:8px">No evidence linked yet.</p>`);
      setHTML(m.el.querySelector('[data-part="ev-suggested"]'), suggestedList(entry.suggested, items, writable));
    };
    const drawRefPicker = () => {
      const slot = m.el.querySelector('[data-part="ev-ref"]');
      if (!slot) return;
      const kind = q("ev_kind").value;
      const pickFrom = (opts, empty) => (opts.length ? html`<select name="ev_ref" aria-label="Evidence">${options(opts)}</select>`
        : html`<select name="ev_ref" disabled aria-label="Evidence"><option value="">${empty}</option></select>`);
      setHTML(slot, kind === "control" ? pickFrom(pick.controls.map((c) => [c.id, `${c.id} ${c.title} (${c.status})`]), "No controls")
        : kind === "policy" ? pickFrom(pick.policies.map((p) => [p.id, `${p.title} (${p.status}, v${p.version})`]), "No policies yet")
          : kind === "risk" ? pickFrom(pick.risks.map((x) => [x.id, `${x.title} (score ${x.score}, ${x.status.replace(/_/g, " ")})`]), "No risks recorded")
            : kind === "url" ? html`<input name="ev_ref" type="url" maxlength="1000" placeholder="https://..." aria-label="URL">`
              : html`<input name="ev_ref" maxlength="1000" placeholder="e.g. ISMS share: backup-test-2026.pdf" aria-label="File name or location">`);
    };
    const hint = () => {
      for (const dim of ["implementation", "documentation"]) {
        const v = Number(q(dim).value);
        m.el.querySelector(`[data-hint="${dim}"]`).textContent = v ? detail.scale.find((s) => s.score === v)?.[dim] || "" : "Not scored yet.";
      }
      const na = q("na").checked;
      m.el.querySelector("[data-na-box]").hidden = !na;
      const i = Number(q("implementation").value);
      const doc = Number(q("documentation").value);
      m.el.querySelector("[data-preview]").textContent = na ? `N/A: counts as ${fmt(fw.conformity.na_counts_as)} in the averages; the scores are kept but not counted.`
        : i ? `Requirement maturity ${fmt((i + (doc || 1)) / 2)}${doc ? "" : " (documentation not scored counts as 1)"}; target ${fmt(goal)}.`
          : "Not scored: left out of the averages; a key measure not scored fails its rule.";
    };
    const add = (item) => {
      if (items.some((e) => e.kind === item.kind && e.ref === item.ref)) return toast("Already linked", "warn");
      if (items.length >= 25) return toast("At most 25 evidence links per requirement", "warn");
      items.push(item);
      drawEvidence();
    };
    actions(m.el, {
      "ev-add"() {
        const kind = q("ev_kind").value;
        const refEl = q("ev_ref");
        const value = (refEl?.value || "").trim();
        if (!value) return toast("Choose or enter the evidence first", "warn");
        if (kind === "url" && !URL_RE.test(value)) return toast("A link must start with http:// or https:// and carry no user name or password", "warn");
        const record = (kind === "control" ? pick.controls : kind === "policy" ? pick.policies : kind === "risk" ? pick.risks : []).find((x) => x.id === value);
        add({ kind, ref: value, title: q("ev_title").value.trim(), display: record?.title, status: kind === "control" ? record?.status : undefined });
        q("ev_title").value = "";
        if (kind === "url" || kind === "file") refEl.value = "";
      },
      "ev-remove"(d) { items.splice(Number(d.i), 1); drawEvidence(); },
      "ev-link"(d) {
        const s = entry.suggested.find((x) => x.control === d.control);
        add({ kind: "control", ref: d.control, title: "", display: s?.title, status: s?.status, detail: s?.detail });
      },
    });
    m.el.addEventListener("change", (e) => { if (e.target.name === "ev_kind") drawRefPicker(); else hint(); });
    m.el.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && e.target.name?.startsWith("ev_")) { e.preventDefault(); m.el.querySelector('[data-act="ev-add"]')?.click(); }
    });
    drawEvidence();
    drawRefPicker();
    hint();
  };

  // ---------- assessment-level actions ----------
  const openEdit = () => {
    const archived = detail.status === "archived";
    const statusField = field("Status", html`<select name="status">${options(STATUSES, detail.status)}</select>`, "Archived assessments are read-only and not sent to CISO Assistant.");
    const m = modal({
      title: "Edit self-assessment", wide: true, minRole: "operator",
      body: archived
        ? html`<div class="notice warn" style="margin-bottom:12px">${icon("lock")}<div><b>Archived.</b>
            <span class="muted">Its name, target level, scope and notes are read-only: set the status to In progress to reopen it first.</span></div></div>
          ${statusField}`
        : html`${field("Name", html`<input name="name" required maxlength="200" value="${detail.name}">`)}
        <div class="form-grid">${field("Target level", html`<select name="target_level">${options(fw.levels.map((l) => [l.id, `${l.name} (${l.requirements} requirements)`]), detail.target_level)}</select>`,
          "Changes which requirements count and the rules applied.")}
          ${statusField}</div>
        ${field("Scope", html`<textarea name="scope" rows="2" maxlength="4000">${detail.scope}</textarea>`)}
        ${field("Notes", html`<textarea name="notes" rows="3" maxlength="8000">${detail.notes}</textarea>`)}`,
      footer: html`<button type="button" class="btn danger" data-del style="margin-right:auto" data-min-role="admin">${icon("trash")}Delete</button>
        <button type="button" class="btn" data-close>Cancel</button><button type="submit" class="btn primary" data-min-role="operator">Save</button>`,
      async onSubmit(d) {
        const next = archived ? { status: d.get("status") } : { name: String(d.get("name") || "").trim(), target_level: d.get("target_level"), status: d.get("status"),
          scope: String(d.get("scope") || "").trim(), notes: String(d.get("notes") || "").trim() };
        if (!archived && !next.name) throw new Error("The name cannot be empty");
        const changed = Object.fromEntries(Object.entries(next).filter(([k, v]) => v !== (detail[k] ?? "")));
        if (!Object.keys(changed).length) return;
        const levelChanged = "target_level" in changed;
        detail = await patch(api, changed);
        if (levelChanged) {
          f.level = detail.target_level;
          pinned.clear();
          drawView();
        }
        redraw();
        toast("Assessment updated", "ok");
      },
    });
    m.el.querySelector("[data-del]").addEventListener("click", () => { m.close(); remove(); });
  };

  const remove = async () => {
    if (!(await confirmDialog("Delete self-assessment", `Delete "${detail.name}" with all its scores, notes and evidence links? This cannot be undone: download the audit pack first if you need a record.`, "Delete"))) return;
    try {
      await del(api);
      toast("Assessment deleted", "ok");
      location.hash = `${BASE}/${enc(fid)}`;
    } catch (err) {
      if (err.status !== 401) toast(err.message, "bad");
    }
  };

  const gone = () => {
    ctx.crumb("Compliance hub / assessment not found");
    setHTML(el, notFound("This assessment was deleted", "Someone deleted it while it was open."));
  };

  actions(el, {
    view: (d) => setView(d.view),
    req: (d) => openRequirement(d.ref).catch((err) => toast(err.message, "bad")),
    edit: openEdit,
    delete: remove,
    pack: (d, btn) => downloadPack(fid, aid, btn),
    async status(d) {
      try {
        detail = await patch(api, { status: d.status });
        redraw();
        toast(d.status === "completed" ? "Marked completed" : d.status === "archived" ? "Archived" : "Reopened", "ok");
      } catch (err) {
        if (err.status !== 401) toast(err.message, "bad");
      }
    },
    "show-status"(d) {
      Object.assign(f, { status: d.status, level: detail.target_level, key: false, mgmt: false, q: "" });
      pinned.clear();
      setView("requirements");
      part("tree")?.scrollIntoView({ behavior: "smooth", block: "start" });
    },
  });
  bindTree(el, f, collapsed, () => { pinned.clear(); drawTree(); });

  // Quick scoring: a selector in a row saves that one value.
  el.addEventListener("change", async (e) => {
    const sel = e.target;
    if (!sel.matches?.("select[data-score]")) return;
    const { ref, score: dim } = sel.dataset;
    const before = detail.requirements[ref][dim];
    const focus = focusKey(el);
    sel.disabled = true;
    try {
      const res = await patch(`${api}/requirements/${enc(ref)}`, { [dim]: sel.value ? Number(sel.value) : null });
      if (!el.isConnected) return;
      apply(res);
      pinned.add(ref);
      redraw(focusKey(el) || focus); // where the person moved on to while saving, else the selector they changed
    } catch (err) {
      sel.value = before ? String(before) : "";
      sel.disabled = false;
      if (err.status !== 401) toast(err.message, "bad");
    }
  });

  drawHead();
  drawNotices();
  drawSummary();
  drawLevels();
  drawViews();
  drawView();

  // ---------- live updates ----------
  // A debounced handler may still fire once the person has left this page: do nothing then.
  const reload = async () => {
    if (!el.isConnected) return;
    const next = await get(api).catch((err) => (err.status === 404 ? null : Promise.reject(err)));
    if (!el.isConnected) return;
    if (!next) return gone();
    const same = JSON.stringify([next.requirements, next.evaluation, next.status, next.name, next.target_level, next.scope, next.notes])
      === JSON.stringify([detail.requirements, detail.evaluation, detail.status, detail.name, detail.target_level, detail.scope, detail.notes]);
    const levelChanged = next.target_level !== detail.target_level;
    detail = next;
    if (levelChanged) { f.level = detail.target_level; drawView(); }
    if (!same) redraw();
  };
  ctx.live(["framework_assessment", "framework_assessment_removed"], async () => {
    if (!el.isConnected) return;
    const briefs = await get(`/frameworks/${enc(fid)}/assessments`).catch(() => null);
    if (!briefs || !el.isConnected) return;
    const mine = briefs.find((b) => b.id === aid);
    if (!mine) gone();
    else if (mine.updated_at !== detail.updated_at) reload().catch(() => {});
  }, 500);
  ctx.live(["grc", "policy", "policy_removed", "risk", "risk_removed"], () => reload().catch(() => {}), 800);
  ctx.live(["person", "person_removed"], async () => {
    if (!el.isConnected) return;
    people = await loadPeople();
    byId = Object.fromEntries(people.map((p) => [p.id, p]));
    reload().catch(() => {});
  }, 800);
  ctx.live(["external_framework", "external_framework_removed", "flow", "flow_removed", "connection"], async () => {
    if (!el.isConnected) return;
    const l = await get("/frameworks").catch(() => null);
    if (!l || !el.isConnected) return;
    list = l;
    drawHead();
    if (view === "details") drawView();
  }, 800);
}

// ---------- a framework read from CISO Assistant (read-only) ----------

function extNode(n, q, results) {
  const kids = (n.children || []).map((c) => extNode(c, q, results)).filter(Boolean);
  const self = !q || `${n.ref_id || ""} ${n.name || ""} ${n.description || ""}`.toLowerCase().includes(q);
  if (!self && !kids.length) return null;
  const res = n.assessable ? results.get(n.urn) || results.get(`ref:${n.ref_id}`) : null;
  const head = html`${n.ref_id ? html`<code>${n.ref_id}</code> ` : ""}<span>${n.name || ""}</span>
    ${(n.implementation_groups || []).map((g) => html` <span class="badge">${g}</span>`)}
    ${res ? html` <span class="badge ${RESULT_TONES[res.result] || ""}">${res.result.replace(/_/g, " ")}</span>${res.score != null ? html` <span class="faint" style="font-size:12px">impl. ${res.score}${res.documentation_score != null ? `, doc. ${res.documentation_score}` : ""}</span>` : ""}` : ""}`;
  const desc = n.description ? html`<div class="fw-desc faint">${n.description}</div>` : "";
  if (!kids.length) return html`<div class="fw-ext-leaf">${head}${desc}</div>`;
  return html`<details class="fw-ext" ${q || (n.depth || 1) <= 1 ? "open" : ""}><summary>${head}</summary><div class="fw-ext-body">${desc}${kids}</div></details>`;
}

async function renderExternal(el, ctx, id) {
  let fw;
  const load = async () => {
    try {
      return await get(`/frameworks/${enc(id)}`);
    } catch (err) {
      if (err.status === 404) return null;
      throw err;
    }
  };
  fw = await load();
  if (!el.isConnected) return;
  const missing = () => {
    ctx.crumb("Compliance hub / framework not found");
    setHTML(el, notFound("Framework not found", "It was read from CISO Assistant: the connection may have been removed, or the framework is no longer loaded there."));
  };
  if (!fw) return missing();
  const state = { q: "", pick: fw.assessments[0]?.external_id || "" };
  const part = (n) => el.querySelector(`[data-part="${n}"]`);

  setHTML(el, html`<nav class="fw-crumbs" aria-label="Breadcrumb"><a href="${BASE}">Frameworks</a> / <span>from CISO Assistant</span></nav>
    <div data-part="head"></div>
    <section class="card" style="margin-top:16px"><header><h2>Requirements</h2><span class="faint" style="font-size:12px" data-part="count"></span></header>
      <div class="row filters fw-filters"><span data-part="pick"></span><span class="spacer"></span>
        <input data-ext="q" placeholder="Search id, name or description..." style="max-width:280px" aria-label="Search requirements"></div>
      <div data-part="tree"></div></section>`);

  const drawHead = () => {
    ctx.crumb(`Compliance hub / ${fw.name}`);
    setHTML(part("head"), html`<section class="card"><div class="fw-title" style="margin-bottom:8px"><div style="min-width:0"><h2 class="fw-name">${fw.name}</h2>
        <div class="row" style="gap:6px;margin-top:6px">${badge("read-only", "info")}${fw.provider ? html`<span class="badge">${fw.provider}</span>` : ""}${fw.ref_id ? html`<span class="badge mono">${fw.ref_id}</span>` : ""}
          <span class="faint" style="font-size:12px">read from <a href="#/tools/${enc(fw.source.tool_id)}">${fw.source.tool_name}</a> ${timeAgo(fw.source.pulled_at)}</span></div></div></div>
      ${fw.caveat ? html`<div class="notice warn" style="margin-bottom:10px">${icon("alert")}<div><b>Check the source text.</b> ${fw.caveat}</div></div>` : ""}
      <p class="faint" style="font-size:12.5px;margin-bottom:8px">${fw.notice} Assess it in CISO Assistant; Atrium shows its status.</p>
      ${fw.description ? html`<div class="prose-box">${fw.description}</div>` : ""}
      ${fw.implementation_groups.length ? html`<div class="row" style="gap:6px;margin-top:10px"><span class="faint" style="font-size:12.5px">Implementation groups</span>
        ${fw.implementation_groups.map((g) => html`<span class="badge" title="${g.name || ""}">${g.ref_id}${g.name ? ` ${g.name}` : ""}</span>`)}</div>` : ""}</section>
      <section class="card flush" style="margin-top:16px"><header><h2>Assessments in CISO Assistant</h2></header>
        ${fw.assessments.length ? html`<div class="table-wrap" style="margin-top:8px"><table class="table compact"><thead><tr><th>Assessment</th><th>Status</th><th>Groups</th><th>Maturity</th><th>Results</th><th>Outcomes</th><th>Updated</th></tr></thead><tbody>
          ${fw.assessments.map((a) => html`<tr><td>${a.name || a.external_id}</td><td>${a.status ? badge(a.status) : "-"}</td><td>${(a.selected_implementation_groups || []).join(", ") || "-"}</td>
            <td>${fmt(a.scores?.maturity)}${a.scores?.implementation != null ? html` <span class="faint" style="font-size:12px">impl. ${fmt(a.scores.implementation)}, doc. ${fmt(a.scores.documentation)}</span>` : ""}</td>
            <td><span class="tag-list">${Object.entries(a.results || {}).filter(([, n]) => n).map(([k, n]) => html`<span class="badge ${RESULT_TONES[k] || ""}">${n} ${k.replace(/_/g, " ")}</span>`)}</span></td>
            <td>${(a.outcomes || []).join(", ") || "-"}</td><td class="faint">${a.updated_at || ""}</td></tr>`)}</tbody></table></div>`
        : html`<p class="muted" style="padding:0 16px 14px">No compliance assessment of this framework in CISO Assistant.</p>`}</section>
      ${fw.mappings.length ? html`<section class="card" style="margin-top:16px"><header><h2>Mapping sets</h2></header>
        ${fw.mappings.map((x) => html`<div style="font-size:12.5px;padding:4px 0"><b>${x.name || x.external_id}</b> <span class="faint mono" style="overflow-wrap:anywhere">${x.source} &rarr; ${x.target}</span></div>`)}</section>` : ""}`);
    setHTML(part("pick"), fw.assessments.length ? html`<select data-ext="pick" class="input-sm" aria-label="Show results of">${options([["", "Without results"],
      ...fw.assessments.map((a) => [a.external_id, `Results of ${a.name || a.external_id}`])], state.pick)}</select>` : "");
  };
  const drawTree = () => {
    const a = fw.assessments.find((x) => x.external_id === state.pick);
    const results = new Map();
    for (const r of a?.requirements || []) {
      if (r.urn) results.set(r.urn, r);
      if (r.ref_id) results.set(`ref:${r.ref_id}`, r);
    }
    const nodes = fw.tree.map((n) => extNode(n, state.q, results)).filter(Boolean);
    setHTML(part("tree"), nodes.length ? html`<div class="fw-ext-tree">${nodes}</div>` : emptyState("search", "No requirement matches", "Change the search to see others."));
    part("count").textContent = `${fw.counts.requirements} assessable of ${fw.counts.nodes} nodes`;
  };
  const typed = debounce(drawTree, 160);
  el.addEventListener("input", (e) => { if (e.target.dataset?.ext === "q") { state.q = e.target.value.trim().toLowerCase(); typed(); } });
  el.addEventListener("change", (e) => { if (e.target.dataset?.ext === "pick") { state.pick = e.target.value; drawTree(); } });
  drawHead();
  drawTree();
  ctx.live(["external_framework", "external_framework_removed", "connection"], async () => {
    if (!el.isConnected) return;
    const next = await load().catch(() => fw);
    if (!el.isConnected) return;
    if (!next) return missing();
    fw = next;
    if (!fw.assessments.some((x) => x.external_id === state.pick)) state.pick = fw.assessments[0]?.external_id || "";
    drawHead();
    drawTree();
  }, 800);
}
