import { del, get, patch, post } from "../api.js";
import { followPicker, loadPeople, personChip, personOptions } from "../people.js";
import {
  actions, badge, can, confirmDialog, emptyState, field, html, icon, md, modal, options, setHTML, timeAgo, toast,
} from "../ui.js";

const STATUS_ICON = { pass: "check", partial: "minus", fail: "x", manual: "edit", na: "minus" };
const POLICY_CATEGORIES = ["security", "access", "incident", "backup", "acceptable-use", "supplier", "other"];

function frameworksPanel(payload) {
  const items = payload?.frameworks || [];
  return html`<section class="card"><header><h2>Compliance frameworks</h2></header>
    <p class="muted">CyFun 2025 is the default self-assessment. Requirement text stays on cyfun.eu; Atrium stores titles, scores and evidence links. Viewers read, operators score, administrators delete.</p>
    ${items.length ? html`<ul>${items.map((f) => html`<li><b>${f.short_name || f.name}</b> ${f.kind === "external" ? badge("from CISO Assistant", "info") : ""}
      ${f.default ? badge("default", "ok") : ""} ${f.counts?.requirements ? html`<span class="faint">${f.counts.requirements} requirements</span>` : ""}
      ${f.kind === "builtin" && can("operator") ? html`<button class="btn sm" data-act="assess" data-id="${f.id}" data-min-role="operator">Start assessment</button>` : ""}</li>`)}</ul>`
      : html`<p class="muted">No frameworks loaded.</p>`}
    ${(payload?.ciso || []).length ? html`<p class="faint">${payload.ciso.length} CISO Assistant connection(s).</p>` : ""}</section>`;
}

function riskColor(score) {
  if (score >= 15) return "#dc2626";
  if (score >= 9) return "#ea580c";
  if (score >= 5) return "#ca8a04";
  return "#16a34a";
}

function heatmap(risks) {
  const open = risks.filter((r) => r.status !== "closed");
  const cells = [];
  for (let l = 5; l >= 1; l--) {
    cells.push(html`<div class="axis">${l}</div>`);
    for (let i = 1; i <= 5; i++) {
      const n = open.filter((r) => r.likelihood === l && r.impact === i).length;
      cells.push(html`<div class="cell" style="background:${riskColor(l * i)};opacity:${n ? 1 : 0.28}" title="Likelihood ${l} x impact ${i}: ${n} open">${n || ""}</div>`);
    }
  }
  cells.push(html`<div></div>`, ...[1, 2, 3, 4, 5].map((i) => html`<div class="axis">${i}</div>`));
  return html`<div class="heat">${cells}</div><div class="row faint" style="justify-content:space-between;font-size:11px;margin-top:6px"><span>&uarr; likelihood</span><span>impact &rarr;</span></div>`;
}

function frameworkCards(frameworks) {
  return html`<div class="grid cols-5" style="margin-bottom:16px">${frameworks.map((f) => html`<div class="card">
    <div class="row" style="justify-content:space-between"><b>${f.name}</b><span style="font-size:20px;font-weight:750">${f.score ?? "-"}%</span></div>
    <div class="progress" style="margin:10px 0 8px"><span style="width:${f.score || 0}%"></span></div>
    <div class="faint" style="font-size:12px">${f.passing}/${f.controls} controls passing${f.failing ? `, ${f.failing} failing` : ""}</div></div>`)}</div>`;
}

function controlRow(c) {
  return html`<div class="check-row">
    <div class="ico ${c.status}">${icon(STATUS_ICON[c.status])}</div>
    <div style="flex:1;min-width:0">
      <div class="row" style="gap:8px"><code>${c.id}</code><b>${c.title}</b>${badge(c.status === "na" ? "n/a" : c.status)}${c.manual ? badge("set by hand", "info") : c.automated ? badge("automated", "accent") : ""}</div>
      <div class="muted" style="margin-top:2px">${c.description}</div>
      <div style="margin-top:4px;font-size:13px">${c.detail}${c.note ? html` <span class="faint">- ${c.note}</span>` : ""}</div>
      ${c.evidence.length ? html`<details style="margin-top:4px"><summary class="faint" style="cursor:pointer;font-size:12px">Evidence (${c.evidence.length})</summary>
        <ul style="margin:4px 0;padding-left:18px;font-size:12.5px">${c.evidence.map((e) => html`<li>${e}</li>`)}</ul></details>` : ""}
      <div class="row" style="gap:6px;margin-top:6px">${Object.entries(c.refs).map(([k, v]) => html`<span class="badge">${k} ${v}</span>`)}</div>
    </div>
    <div data-min-role="operator"><button class="btn sm" data-act="override" data-id="${c.id}">${icon("edit")}Set</button></div></div>`;
}

/** Owner picker (a person in the People app) next to the free-text owner that is shown. */
const ownerFields = (item, people) => html`
  ${field("Owner", html`<select name="owner_person_id">${personOptions(people, item.owner_person_id, { none: "No person" })}</select>`,
    people.length ? "The accountable person (People app)." : "No people yet - add them in the People app.")}
  ${field("Owner as shown", html`<input name="owner" value="${item.owner || ""}" placeholder="person or team">`, "Free text; picking a person fills it.")}`;

const ownerData = (d) => ({ owner: String(d.get("owner") || "").trim() || null, owner_person_id: d.get("owner_person_id") || null });

/** An owner cell: the linked person, else the free text. */
const ownerCell = (item, byId) => (byId[item.owner_person_id] ? personChip(byId[item.owner_person_id], { link: false }) : item.owner || html`<span class="faint">-</span>`);

function riskForm(r = {}, people = []) {
  return html`${field("Title", html`<input name="title" value="${r.title || ""}" required>`)}
    ${field("Description", html`<textarea name="description" rows="3">${r.description || ""}</textarea>`)}
    <div class="form-grid">
      ${field("Likelihood (1-5)", html`<select name="likelihood">${options([1, 2, 3, 4, 5].map((n) => [String(n), String(n)]), String(r.likelihood || 3))}</select>`)}
      ${field("Impact (1-5)", html`<select name="impact">${options([1, 2, 3, 4, 5].map((n) => [String(n), String(n)]), String(r.impact || 3))}</select>`)}
      ${ownerFields(r, people)}
      ${field("Category", html`<input name="category" value="${r.category || "security"}">`)}
      ${field("Treatment", html`<select name="treatment">${options(["mitigate", "accept", "transfer", "avoid"], r.treatment || "mitigate")}</select>`)}
      ${field("Status", html`<select name="status">${options(["open", "in_treatment", "closed"], r.status || "open")}</select>`)}</div>
    ${r.source && r.source !== "manual" ? html`<p class="faint" style="font-size:12px">Raised by the GRC Supervisor from control ${r.control_ids?.join(", ")}. It closes automatically when the control passes.</p>` : ""}`;
}

const riskData = (d) => ({
  title: d.get("title"), description: d.get("description"), likelihood: Number(d.get("likelihood")), impact: Number(d.get("impact")),
  ...ownerData(d), category: d.get("category") || "security", treatment: d.get("treatment"), status: d.get("status"),
});

function policyForm(p = {}, people = []) {
  return html`<div class="form-grid">
      ${field("Title", html`<input name="title" value="${p.title || ""}" required>`)}
      ${field("Category", html`<select name="category">${options(POLICY_CATEGORIES, p.category || "security")}</select>`)}
      ${ownerFields(p, people)}
      ${field("Version", html`<input name="version" value="${p.version || "0.1"}">`)}
      ${field("Status", html`<select name="status">${options(["draft", "approved", "retired"], p.status || "draft")}</select>`)}
      ${field("Review due", html`<input name="review_due" type="date" value="${p.review_due || ""}">`)}</div>
    ${field("Policy text (Markdown)", html`<textarea name="body" rows="14" class="mono" style="font-size:12.5px">${p.body || ""}</textarea>`)}`;
}

const policyData = (d) => ({
  title: d.get("title"), category: d.get("category"), ...ownerData(d), version: d.get("version") || "0.1",
  status: d.get("status"), review_due: d.get("review_due") || null, body: d.get("body") || "",
});

export async function render(el, ctx) {
  let tab = ctx.params[0] || "overview";
  let data, risks, policies;
  let people = [];
  let frameworks = null;
  let byId = {};
  const draw = async () => {
    let frameworks = null;
    [data, risks, policies, people, frameworks] = await Promise.all([
      get("/grc"), get("/grc/risks"), get("/grc/policies"), loadPeople(),
      tab === "frameworks" ? get("/frameworks") : null,
    ]);
    byId = Object.fromEntries(people.map((p) => [p.id, p]));
    const failing = data.controls.filter((c) => c.status === "fail" || c.status === "partial");
    const openRisks = risks.filter((r) => r.status !== "closed").sort((a, b) => b.score - a.score);
    const families = [...new Set(data.controls.map((c) => c.family))];
    setHTML(el, html`
      <div class="page-head"><div><h1>Compliance hub</h1><p class="muted">Governance, risk and compliance. The GRC Supervisor checks controls against live hub state and maps the evidence to ISO 27001, SOC 2 and NIS2.</p></div>
        <button class="btn" data-act="evaluate" data-min-role="operator">${icon("refresh")}Re-evaluate</button></div>
      <div class="tabs">${[["overview", "Overview"], ["controls", `Controls (${data.controls.length})`], ["frameworks", "Frameworks"], ["risks", `Risks (${openRisks.length} open)`], ["policies", `Policies (${policies.length})`]]
        .map(([k, label]) => html`<button class="${tab === k ? "active" : ""}" data-act="tab" data-tab="${k}">${label}</button>`)}</div>

      ${tab === "overview" ? html`${frameworkCards(data.frameworks)}
        <div class="grid split">
          <section class="card"><header><h2>Needs attention</h2><a href="#/compliance/controls" data-act="tab" data-tab="controls">All controls &rarr;</a></header>
            ${failing.length ? failing.slice(0, 8).map(controlRow) : html`<p class="muted">Every automated control passes.</p>`}</section>
          <section class="stack">
            <div class="card"><header><h2>Risk heatmap</h2><span class="faint" style="font-size:12px">${openRisks.length} open</span></header>${heatmap(risks)}</div>
            <div class="card"><header><h3>Top risks</h3></header>${openRisks.length ? openRisks.slice(0, 5).map((r) => html`<div class="msg-line" style="grid-template-columns:auto 1fr">
              <span class="badge" style="background:${riskColor(r.score)};color:#fff;border:0">${r.score}</span><span>${r.title}</span></div>`) : html`<p class="muted">No open risks.</p>`}</div>
          </section></div>` : ""}

      ${tab === "frameworks" ? frameworksPanel(frameworks) : ""}

      ${tab === "controls" ? html`${families.map((fam) => html`<section class="card" style="margin-bottom:12px"><header><h2>${fam}</h2></header>
        ${data.controls.filter((c) => c.family === fam).map(controlRow)}</section>`)}` : ""}

      ${tab === "risks" ? html`<div class="grid split">
          <section class="card flush"><header><h2>Risk register</h2><button class="btn sm primary" data-act="add-risk" data-min-role="operator">${icon("plus")}Add risk</button></header>
            ${risks.length ? html`<div class="table-wrap" style="margin-top:10px"><table class="table"><thead><tr><th>Score</th><th>Risk</th><th>Owner</th><th>Treatment</th><th>Status</th><th>Reviewed</th></tr></thead><tbody>
              ${risks.slice().sort((a, b) => (a.status === "closed") - (b.status === "closed") || b.score - a.score).map((r) => html`<tr class="clickable" data-act="edit-risk" data-id="${r.id}">
                <td><span class="badge" style="background:${riskColor(r.score)};color:#fff;border:0">${r.score}</span></td>
                <td><b>${r.title}</b>${r.source !== "manual" ? html` <span class="badge accent">auto</span>` : ""}<div class="faint" style="font-size:12px">${r.category}</div></td>
                <td>${ownerCell(r, byId)}</td><td>${r.treatment}</td><td>${badge(r.status)}</td><td class="faint">${timeAgo(r.reviewed_at || r.created_at)}</td></tr>`)}
              </tbody></table></div>` : emptyState("alert", "No risks recorded", "Add risks by hand; the GRC Supervisor also raises them when controls fail.")}</section>
          <section class="card"><header><h2>Heatmap</h2></header>${heatmap(risks)}</section></div>` : ""}

      ${tab === "policies" ? html`<section class="card"><header><h2>Policies</h2>
          <div class="row" data-min-role="operator"><select id="tpl" aria-label="Policy template"><option value="">New from template...</option>${options(POLICY_CATEGORIES.slice(0, 6))}</select>
            <button class="btn sm primary" data-act="add-policy">${icon("plus")}Blank policy</button></div></header>
          ${policies.length ? policies.map((p) => html`<div class="check-row"><div class="stat-icon">${icon("file")}</div>
            <div style="flex:1;min-width:0"><div class="row" style="gap:8px"><b>${p.title}</b>${badge(p.status)}<span class="badge">${p.category}</span><span class="faint">v${p.version}</span></div>
              <div class="faint row" style="font-size:12px;gap:4px">${byId[p.owner_person_id] ? html`Owner ${personChip(byId[p.owner_person_id])}` : p.owner ? `Owner ${p.owner}` : "No owner"}
                <span>${p.review_due ? ` - review due ${p.review_due}` : ""} - updated ${timeAgo(p.updated_at)}</span></div></div>
            <div class="row" style="gap:6px">${p.status !== "approved" ? html`<button class="btn sm ok" data-act="approve-policy" data-id="${p.id}" data-min-role="operator">${icon("check")}Approve</button>` : ""}
              <button class="btn sm" data-act="edit-policy" data-id="${p.id}">${can("operator") ? html`${icon("edit")}Edit` : html`${icon("file")}View`}</button></div></div>`)
          : emptyState("file", "No policies yet", "Start from a template - the GRC Supervisor counts approved policies as evidence.")}</section>` : ""}`);
    el.querySelector("#tpl")?.addEventListener("change", async (e) => {
      const cat = e.target.value;
      if (!cat) return;
      const templates = await get("/grc/policy-templates");
      openPolicy({ ...templates[cat], category: cat });
    });
  };

  const openPolicy = (p, existing = false) => {
    const m = modal({
      title: existing ? p.title : "New policy", body: policyForm(p, people), wide: true, submit: "Save", minRole: "operator",
      footer: html`${existing ? html`<button type="button" class="btn danger" data-del style="margin-right:auto" data-min-role="operator">${icon("trash")}Delete</button>` : ""}
        <button type="button" class="btn" data-preview>Preview</button><button type="button" class="btn" data-close>${can("operator") ? "Cancel" : "Close"}</button>
        <button type="submit" class="btn primary" data-min-role="operator">Save</button>`,
      async onSubmit(d) {
        if (existing) await patch(`/grc/policies/${p.id}`, policyData(d)); else await post("/grc/policies", policyData(d));
        toast("Policy saved", "ok");
        draw();
      },
    });
    followPicker(m.el.querySelector("[name=owner_person_id]"), m.el.querySelector("[name=owner]"), people);
    m.el.querySelector("[data-preview]").addEventListener("click", () => {
      modal({ title: "Preview", body: html`<div class="policy-body">${md(m.el.querySelector("[name=body]").value)}</div>`, submit: null, cancel: "Close", wide: true });
    });
    m.el.querySelector("[data-del]")?.addEventListener("click", async () => {
      m.close();
      if (await confirmDialog("Delete policy", `Delete "${p.title}"?`, "Delete")) { await del(`/grc/policies/${p.id}`); draw(); }
    });
  };

  actions(el, {
    tab: (d) => { tab = d.tab; history.replaceState(null, "", `#/compliance/${tab}`); draw(); },
    async assess(d) {
      const name = window.prompt("Name this self-assessment");
      if (!name) return;
      await post(`/frameworks/${d.id}/assessments`, { name, target_level: "B" });
      toast("Assessment started", "ok");
    },
    async evaluate() { await post("/grc/evaluate"); toast("Controls re-evaluated", "ok"); draw(); },
    override(d) {
      const c = data.controls.find((x) => x.id === d.id);
      const m = modal({
        title: `${c.id} ${c.title}`,
        minRole: "operator",
        body: html`<p class="muted" style="margin-bottom:12px">${c.description}</p>
          ${field("Status", html`<select name="status">${options([["pass", "Pass"], ["partial", "Partial"], ["fail", "Fail"], ["na", "Not applicable"]], c.status)}</select>`)}
          ${field("Justification / evidence", html`<textarea name="note" rows="3" placeholder="e.g. Backups handled by the hosting provider, contract ref. 2026-14">${c.note || ""}</textarea>`)}
          ${c.automated ? html`<p class="faint" style="font-size:12px">This control is automated. A status set by hand overrides the check until you switch it back.</p>` : ""}`,
        footer: html`${c.manual ? html`<button type="button" class="btn" data-auto style="margin-right:auto" data-min-role="operator">Back to automatic</button>` : ""}
          <button type="button" class="btn" data-close>Cancel</button><button type="submit" class="btn primary" data-min-role="operator">Save</button>`,
        async onSubmit(f) { await patch(`/grc/controls/${c.id}`, { status: f.get("status"), note: f.get("note") || null }); toast("Control updated", "ok"); draw(); },
      });
      m.el.querySelector("[data-auto]")?.addEventListener("click", async () => { m.close(); await patch(`/grc/controls/${c.id}`, { clear: true }); draw(); });
    },
    "add-risk"() {
      const m = modal({ title: "Add risk", body: riskForm({}, people), submit: "Add", wide: true, minRole: "operator",
        async onSubmit(d) { await post("/grc/risks", riskData(d)); toast("Risk added", "ok"); draw(); } });
      followPicker(m.el.querySelector("[name=owner_person_id]"), m.el.querySelector("[name=owner]"), people);
    },
    "edit-risk"(d) {
      const r = risks.find((x) => x.id === d.id);
      const m = modal({
        title: r.title, body: riskForm(r, people), wide: true, minRole: "operator",
        footer: html`<button type="button" class="btn danger" data-del style="margin-right:auto" data-min-role="operator">${icon("trash")}Delete</button>
          <button type="button" class="btn" data-close>${can("operator") ? "Cancel" : "Close"}</button><button type="submit" class="btn primary" data-min-role="operator">Save &amp; mark reviewed</button>`,
        async onSubmit(f) { await patch(`/grc/risks/${r.id}`, riskData(f)); toast("Risk updated", "ok"); draw(); },
      });
      followPicker(m.el.querySelector("[name=owner_person_id]"), m.el.querySelector("[name=owner]"), people);
      m.el.querySelector("[data-del]").addEventListener("click", async () => {
        m.close();
        if (await confirmDialog("Delete risk", `Delete "${r.title}"?`, "Delete")) { await del(`/grc/risks/${r.id}`); draw(); }
      });
    },
    "add-policy"() { openPolicy({}); },
    "edit-policy"(d) { openPolicy(policies.find((p) => p.id === d.id), true); },
    async "approve-policy"(d) {
      await patch(`/grc/policies/${d.id}`, { status: "approved" });
      toast("Policy approved - evidence updated", "ok");
      draw();
    },
  });
  await draw();
  ctx.live(["grc", "risk", "risk_removed", "policy", "policy_removed", "person_removed"], draw, 600);
}
