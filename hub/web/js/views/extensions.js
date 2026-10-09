// Extensions: the packs that teach Atrium new data types, connector mappings, SSO recipes, compliance evidence and agent-team
// templates (administrators manage them, everyone reads), the gaps imported tools leave in Atrium, and self-patches - changes
// to Atrium's own code that the Patch Agent proposes when a pack cannot express what a tool needs.
import { del, get, patch, post } from "../api.js";
import {
  downloadJson, jsonView, modeView, openExtend, packHref, packItems, safeUrl, summaryChips, testsView, xColor, xHref,
} from "../extensions.js";
import {
  actions, badge, builtinIcon, can, confirmDialog, dateTime, diffView, emptyState, field, html, icon, modal, options, setHTML, timeAgo, toast,
} from "../ui.js";

const enc = encodeURIComponent;
const TABS = ["packs", "gaps", "self-patches"];
const GAP_ICON = { domain: "database", connector: "plug", sso: "shield" };
const CATEGORY = { siem: "SIEM", ticketing: "service desk", monitoring: "monitoring" };
const LIVE = ["extension", "extension_removed", "self_patch", "restart_required", "tool", "tool_removed", "approval", "connection"];
const MAX_PACK = 512_000;
const EXAMPLE = {
  id: "acme-alerts", name: "Acme Monitor alerts", version: "1.0.0",
  description: "Alerts from Acme Monitor, linked to assets by their host.",
  items: [
    { kind: "domain", key: "acme_alerts", title: "Acme alerts", singular: "Acme alert", icon: "bell",
      fields: [{ name: "title", label: "Title", required: true }, { name: "severity", label: "Severity", type: "severity" },
        { name: "status", label: "Status", type: "enum", values: ["open", "acknowledged", "closed"] },
        { name: "host", label: "Host" }, { name: "raised", label: "Raised", type: "date" }, { name: "url", label: "Link", type: "link" }],
      title_field: "title", links: [{ target: "asset", field: "host" }] },
    { kind: "controls", rules: [{ control: "HB-IR-1", domain: "acme_alerts", title: "Critical Acme alerts open for more than 3 days",
      where: [{ field: "severity", op: "eq", value: "critical" }, { field: "status", op: "ne", value: "closed" }],
      age_field: "raised", older_than_days: 3, fail_above: 0 }] },
  ],
};

// ---------- uploading, details, versions ----------

/** Upload a pack (a new pack, or a new version of one). */
export function openUpload(done) {
  const m = modal({
    title: "Upload an extension pack",
    wide: true,
    minRole: "admin",
    submit: "Upload",
    body: html`<p class="muted" style="margin-bottom:12px">A pack is JSON: an id, a name, a version and its items - <code>domain</code>, <code>connector</code>,
        <code>sso</code>, <code>controls</code> and <code>team</code>. It is validated strictly and is data only: nothing in it is ever executed.
        An existing id with a new version adds that version, active at once when the pack is enabled.</p>
      <div class="row" style="margin-bottom:12px"><label class="btn sm">${icon("upload")}Choose a file<input type="file" accept=".json,application/json" data-file hidden></label>
        <button type="button" class="btn sm" data-example>${icon("file")}Insert an example</button><span class="faint" data-file-name style="font-size:12px"></span></div>
      ${field("Pack (JSON)", html`<textarea name="pack" rows="16" class="mono" spellcheck="false" style="font-size:12px"
        placeholder='{"id": "my-pack", "name": "My pack", "version": "1.0.0", "items": [...]}'></textarea>`,
        "At most 512 KB. A pack never carries credentials: API tokens go into the tool's connection.")}
      <label class="check"><input type="checkbox" name="enable"><span>Enable it right away</span></label>`,
    async onSubmit(data) {
      const text = String(data.get("pack") || "").trim();
      if (!text) return toast("Paste a pack or choose a file", "bad"), true;
      if (text.length > MAX_PACK) return toast("The pack is larger than 512 KB", "bad"), true;
      let body;
      try {
        body = JSON.parse(text);
      } catch (err) {
        return toast(`Not valid JSON: ${err.message}`, "bad"), true;
      }
      const enable = data.get("enable") === "on";
      const rec = await post(`/extensions?enable=${enable}`, body);
      toast(`${rec.name} ${rec.version} uploaded${rec.status === "enabled" ? " - enabled" : ""}`, "ok");
      done?.(rec);
    },
  });
  const area = m.el.querySelector("[name=pack]");
  m.el.querySelector("[data-example]").addEventListener("click", () => { area.value = JSON.stringify(EXAMPLE, null, 2); });
  m.el.querySelector("[data-file]").addEventListener("change", async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > MAX_PACK) return toast("The file is larger than 512 KB", "bad");
    area.value = await file.text();
    m.el.querySelector("[data-file-name]").textContent = file.name;
  });
}

function versionsView(p) {
  return html`<p class="muted" style="margin-bottom:10px">Every version is kept. Making another version current takes effect at once when the pack is enabled
      (its connector mappings are applied again); records are kept.</p>
    <div class="table-wrap"><table class="table compact"><thead><tr><th>Version</th><th>Name</th><th>Added</th><th></th></tr></thead><tbody>
      ${p.versions.slice().reverse().map((v) => html`<tr><td><b class="mono">${v.version}</b> ${v.current ? badge("current", "ok") : ""}</td><td>${v.name}</td>
          <td class="faint" title="${dateTime(v.created_at)}">${v.created_by || "-"} - ${timeAgo(v.created_at)}</td>
          <td style="text-align:right;white-space:nowrap"><button type="button" class="btn sm" data-act="show-version" data-version="${v.version}">JSON</button>
            ${v.current ? "" : html`<button type="button" class="btn sm" data-act="use-version" data-version="${v.version}" data-min-role="admin">${icon("undo")}Make current</button>`}</td></tr>
        <tr data-version-json="${v.version}" hidden><td colspan="4">${jsonView(v.pack, "300px")}</td></tr>`)}</tbody></table></div>`;
}

function historyView(p) {
  const rows = (p.history || []).slice().reverse();
  return rows.length ? html`<div class="feed">${rows.map((h) => html`<div class="feed-item"><span class="dot" style="margin-top:7px"></span>
      <div><span class="who">${h.actor}</span> <span class="muted">${h.action}</span> <span class="badge mono">${h.version}</span></div>
      <span class="when" title="${dateTime(h.at)}">${timeAgo(h.at)}</span></div>`)}</div>` : html`<p class="muted">No changes recorded.</p>`;
}

/** A pack's items, JSON, versions and history. */
async function openPack(id, { view = "items", activeDomains = new Set(), done } = {}) {
  let p;
  try {
    p = await get(`/extensions/${enc(id)}`);
  } catch (err) {
    return toast(err.status === 404 ? "That extension no longer exists" : err.message, "bad");
  }
  const views = {
    items: () => packItems(p.pack.items, { pack: p.pack, activeDomains }),
    json: () => html`<p class="faint" style="font-size:12.5px">Version ${p.version} as stored. Upload it again with a higher version to change it.</p>${jsonView(p.pack, "58vh")}`,
    versions: () => versionsView(p),
    history: () => historyView(p),
  };
  const m = modal({
    title: `${p.name} ${p.version}`,
    wide: true,
    footer: html`<button type="button" class="btn" data-act="download" style="margin-right:auto">${icon("download")}Download JSON</button>
      <button type="button" class="btn" data-close>Close</button>`,
    body: html`<div class="row" style="gap:6px;margin-bottom:12px">${badge(p.status)}${p.status === "enabled" && !p.active ? badge("inactive - extensions are off", "warn") : ""}
        <span class="faint mono" style="font-size:12px">${p.id}</span>${p.source_tool ? html`<span class="faint" style="font-size:12px">for ${p.source_tool_name || p.source_tool}</span>` : ""}</div>
      <div class="seg" style="margin-bottom:14px">${[["items", `Items (${p.items.length})`], ["json", "JSON"], ["versions", `Versions (${p.versions.length})`], ["history", "History"]]
        .map(([k, label]) => html`<button type="button" data-view="${k}">${label}</button>`)}</div>
      <div data-pack-view></div>`,
  });
  const show = (k) => {
    m.el.querySelectorAll("[data-view]").forEach((b) => b.classList.toggle("active", b.dataset.view === k));
    setHTML(m.el.querySelector("[data-pack-view]"), views[k]());
  };
  m.el.querySelectorAll("[data-view]").forEach((b) => b.addEventListener("click", () => show(b.dataset.view)));
  actions(m.el, {
    download: () => downloadJson(p.pack, `${p.id}-${p.version}.json`),
    "show-version": (d) => { const row = m.el.querySelector(`[data-version-json="${CSS.escape(d.version)}"]`); if (row) row.hidden = !row.hidden; },
    async "use-version"(d) {
      if (!(await confirmDialog(`Make ${d.version} current?`, `${p.name} switches to version ${d.version}${p.status === "enabled" ? " at once" : ""}. The other versions are kept.`, "Make current"))) return;
      try {
        await post(`/extensions/${enc(p.id)}/rollback`, { version: d.version });
        toast(`${p.name}: version ${d.version} is current`, "ok");
        m.close();
        done?.();
      } catch (err) {
        if (err.status !== 401) toast(err.message, "bad");
      }
    },
  });
  show(views[view] ? view : "items");
}

function openRemove(p, done) {
  const domains = p.summary.domains || [];
  modal({
    title: `Remove ${p.name}?`,
    minRole: "admin",
    submit: "Remove",
    body: html`<p>All ${p.versions.length} version${p.versions.length === 1 ? "" : "s"} of the pack ${p.status === "proposed" ? "are deleted and its proposal is withdrawn." : "are deleted."}
        ${p.status === "enabled" ? "Its apps, SSO recipes, compliance rules and team templates stop at once, its data flows are removed and its connector mappings are taken out of the tools' connections." : ""}</p>
      ${domains.length ? html`<label class="check scope-check" style="margin-top:12px"><input type="checkbox" name="purge">
        <span><b>Also delete the records</b><span class="faint" style="display:block;font-size:12px">Of ${domains.map((k) => `x:${k}`).join(", ")} - unless another enabled pack defines
          the same data type. Without this they stay in the database and come back if a pack defines the type again.</span></span></label>` : ""}`,
    async onSubmit(data) {
      const purge = data.get("purge") === "on";
      const r = await del(`/extensions/${enc(p.id)}${purge ? "?purge=true" : ""}`);
      toast(`${p.name} removed${r.purged ? ` with ${r.purged} record${r.purged === 1 ? "" : "s"}` : ""}`, "ok");
      done?.();
    },
  });
}

// ---------- self-patches ----------

function askForChange(tools, sp, done) {
  modal({
    title: "Ask for a change to Atrium",
    wide: true,
    minRole: "admin",
    submit: "Ask the Patch Agent",
    body: html`<p class="muted" style="margin-bottom:12px">Claude writes the change on a new branch <code>atrium/self-&lt;id&gt;</code> in a separate git worktree
        and runs Atrium's test suite there. It then waits in Approvals with the diff and the test result - your checkout is not touched before that.
        ${sp.via_pull_request ? "On approval it is pushed and opened as a pull request when the GitHub CLI is signed in and an origin remote exists, otherwise merged locally."
          : "On approval it is merged into the current branch (only with a clean working tree) and Atrium must be restarted."}</p>
      ${field("What should change?", html`<textarea name="goal" rows="6" maxlength="4000" required
        placeholder="e.g. Add a connector for Acme's GraphQL API that pulls its alerts into the Alerts app"></textarea>`)}
      ${field("For the tool (optional)", html`<select name="tool_id">${options([["", "No particular tool"], ...tools.map((t) => [t.id, t.name])], "")}</select>`)}`,
    async onSubmit(data) {
      const goal = String(data.get("goal") || "").trim();
      if (!goal) return toast("Describe the change", "bad"), true;
      const r = await post("/self-patches", { goal, tool_id: data.get("tool_id") || null });
      toast(r.detail || "The Patch Agent is on it", "ok");
      done?.();
    },
  });
}

async function openSelfPatch(id, availability, names, done) {
  let sp;
  try {
    sp = await get(`/self-patches/${enc(id)}`);
  } catch (err) {
    return toast(err.status === 404 ? "That self-patch no longer exists" : err.message, "bad");
  }
  const pr = safeUrl(sp.pr_url);
  const m = modal({
    title: sp.title,
    wide: true,
    footer: html`${sp.status === "approved" ? html`<button type="button" class="btn primary" data-act="apply" data-min-role="admin" style="margin-right:auto">${icon("merge")}Apply again</button>` : ""}
      ${sp.status === "proposed" && sp.approval_id ? html`<a class="btn" href="#/approvals">${icon("checkCircle")}Decide in Approvals</a>` : ""}
      <button type="button" class="btn" data-close>Close</button>`,
    body: html`<div class="row" style="gap:6px;margin-bottom:10px">${badge(sp.status)}${sp.tests ? badge(sp.tests_passed ? "tests passed" : "tests failed", sp.tests_passed ? "ok" : "bad") : ""}</div>
      ${sp.error ? html`<div class="notice bad" style="margin-bottom:12px">${icon("alert")}<div style="min-width:0;overflow-wrap:anywhere"><b>Not applied.</b> ${sp.error}
        ${sp.status === "approved" ? html`<div class="muted" style="font-size:12.5px">Fix the cause, then apply it again.</div>` : ""}</div></div>` : ""}
      ${sp.rationale ? html`<p class="muted" style="margin-bottom:10px;white-space:pre-line;overflow-wrap:anywhere">${sp.rationale}</p>` : ""}
      <dl class="kv" style="margin-bottom:12px">
        ${sp.goal ? html`<dt>Asked for</dt><dd style="white-space:pre-line">${sp.goal}</dd>` : ""}
        <dt>Branch</dt><dd><span class="mono">${sp.branch || "-"}</span>${sp.base_branch ? html` <span class="faint">from ${sp.base_branch}${sp.base_commit ? ` @ ${sp.base_commit.slice(0, 10)}` : ""}</span>` : ""}</dd>
        ${sp.commit ? html`<dt>Commit</dt><dd class="mono">${sp.commit.slice(0, 12)}</dd>` : ""}
        <dt>Files</dt><dd><div class="tag-list">${sp.files.map((f) => html`<span class="badge mono">${f}</span>`)}</div></dd>
        ${sp.tool_id ? html`<dt>Tool</dt><dd><a href="#/tools/${enc(sp.tool_id)}">${names[sp.tool_id] || sp.tool_id}</a></dd>` : ""}
        <dt>Requested</dt><dd>${sp.requested_by || "-"} - <span title="${dateTime(sp.created_at)}">${timeAgo(sp.created_at)}</span></dd>
        ${sp.decided_by ? html`<dt>Decided by</dt><dd>${sp.decided_by}</dd>` : ""}
        ${sp.applied_at ? html`<dt>Applied</dt><dd>${dateTime(sp.applied_at)}</dd>` : ""}
        ${pr ? html`<dt>Pull request</dt><dd><a href="${pr}" target="_blank" rel="noopener noreferrer">${pr}</a></dd>` : ""}
        ${sp.merge_commit ? html`<dt>Merged as</dt><dd class="mono">${sp.merge_commit.slice(0, 12)}</dd>` : ""}
      </dl>
      ${sp.mode && !["merged", "pull_request", "rejected"].includes(sp.status) ? html`<div style="margin-bottom:12px">${modeView(sp.mode, sp.mode_reason, sp.base_branch)}</div>` : ""}
      <div style="margin-bottom:12px">${testsView(sp.tests, availability?.requires_tests)}</div>
      <h3 style="margin-bottom:8px">Changes</h3>${diffView(sp.diff)}`,
  });
  actions(m.el, {
    async apply(_, btn) {
      btn.disabled = true;
      try {
        const r = await post(`/self-patches/${enc(sp.id)}/apply`);
        toast(r.detail || (r.ok ? "Applied" : "Not applied"), r.ok ? "ok" : "bad");
        if (r.ok) m.close();
        done?.();
      } catch (err) {
        if (err.status !== 401) toast(err.message, "bad");
      } finally {
        if (btn.isConnected) btn.disabled = false;
      }
    },
  });
}

// ---------- the page ----------

function guardStrip(g) {
  const on = (key) => Boolean(g[key]);
  return html`<div class="guard-strip">${icon("shield")}<span class="faint">Guardrails</span>
    ${badge(on("allow_extensions") ? "extensions allowed" : "extensions switched off", on("allow_extensions") ? "" : "warn")}
    ${badge(`generated packs need approval: ${on("extensions_need_approval") ? "on" : "off"}`, on("extensions_need_approval") ? "ok" : "warn")}
    ${badge(on("allow_self_patching") ? "self-patching allowed" : "self-patching switched off", "")}
    ${badge(`self-patch tests required: ${on("self_patch_requires_tests") ? "on" : "off"}`, on("self_patch_requires_tests") ? "ok" : "bad")}
    ${badge(`self-patch approval required: ${on("self_patch_requires_approval") ? "on" : "off"}`, on("self_patch_requires_approval") ? "ok" : "bad")}
    ${badge(`pull requests: ${on("self_patch_via_pull_request") ? "on" : "off"}`, on("self_patch_via_pull_request") ? "ok" : "warn")}
    <a href="#/settings" data-min-role="admin" style="font-size:12.5px;white-space:nowrap">Change in Settings &rarr;</a></div>`;
}

function packCard(p, admin, names) {
  const previous = p.versions[p.versions.findIndex((v) => v.current) - 1]?.version;
  const applied = Object.entries(p.applied || {});
  const changed = p.updated_at - p.created_at > 5 && p.updated_by;
  return html`<section class="card pack ${p.status} ${p.status === "enabled" && !p.active ? "inactive" : ""}">
    <div class="pack-head">
      <div class="stat-icon">${icon("puzzle")}</div>
      <div style="flex:1;min-width:0">
        <div class="row" style="gap:6px"><h3 style="overflow-wrap:anywhere">${p.name}</h3><span class="badge mono">${p.version}</span>${badge(p.status)}
          ${p.status === "enabled" && !p.active ? badge("inactive", "warn") : ""}</div>
        <div class="faint" style="font-size:12px;margin-top:2px"><span class="mono">${p.id}</span>
          ${p.source_tool ? html` - for <a href="#/tools/${enc(p.source_tool)}">${p.source_tool_name || p.source_tool}</a>` : ""}
          - added by ${p.created_by || "-"} <span title="${dateTime(p.created_at)}">${timeAgo(p.created_at)}</span>${changed ? html`, changed by ${p.updated_by} <span title="${dateTime(p.updated_at)}">${timeAgo(p.updated_at)}</span>` : ""}</div>
      </div>
      <div class="row pack-actions">
        ${p.status === "proposed" ? html`<a class="btn sm" href="#/approvals">${icon("checkCircle")}Approvals</a>
            <span class="row" style="gap:6px" data-min-role="admin"><button type="button" class="btn sm" data-act="status" data-id="${p.id}" data-status="disabled">${icon("x")}Reject</button>
              <button type="button" class="btn sm ok" data-act="status" data-id="${p.id}" data-status="enabled">${icon("check")}Enable</button></span>`
          : html`<button type="button" class="toggle" role="switch" aria-checked="${p.status === "enabled" ? "true" : "false"}" aria-label="${p.status === "enabled" ? "Disable" : "Enable"} ${p.name}"
              title="${admin ? (p.status === "enabled" ? "Disable" : "Enable") : "Only administrators enable or disable packs"}" data-act="toggle" data-id="${p.id}" ${admin ? "" : "disabled"}></button>`}
      </div>
    </div>
    ${p.description ? html`<p class="muted" style="white-space:pre-line;overflow-wrap:anywhere;font-size:13px">${p.description}</p>` : ""}
    ${summaryChips(p.summary)}
    ${applied.length ? html`<div class="faint" style="font-size:12px">${icon("plug")} ${applied.map(([tool, a], i) => html`${i ? "; " : ""}<a href="#/tools/${enc(tool)}/connection">${names[tool] || tool}</a>'s connection
      ${a.created ? "(created by this pack) " : ""}maps ${(a.domains || []).join(", ") || "nothing"}`)}</div>` : ""}
    ${p.notes?.length ? html`<div class="notice warn">${icon("alert")}<ul style="margin:0;padding-left:16px;font-size:12.5px">${p.notes.map((n) => html`<li>${n}</li>`)}</ul></div>` : ""}
    <div class="row" style="gap:6px">
      <button type="button" class="btn sm" data-act="details" data-id="${p.id}">${icon("file")}Items</button>
      <button type="button" class="btn sm" data-act="json" data-id="${p.id}">${icon("copy")}JSON</button>
      <button type="button" class="btn sm" data-act="versions" data-id="${p.id}">${icon("clock")}Versions (${p.versions.length})</button>
      ${p.can_rollback && previous ? html`<button type="button" class="btn sm" data-act="rollback" data-id="${p.id}" data-version="${previous}" data-min-role="admin">${icon("undo")}Roll back to ${previous}</button>` : ""}
      <span class="spacer"></span>
      <button type="button" class="btn sm danger" data-act="remove" data-id="${p.id}" data-min-role="admin">${icon("trash")}Remove</button>
    </div></section>`;
}

function appsCard(domains) {
  return html`<section class="card flush" style="margin-bottom:16px"><header><h2>Extension apps</h2><span class="faint" style="font-size:12px">one per data type an enabled pack adds</span></header>
    <div class="table-wrap" style="margin-top:8px"><table class="table"><thead><tr><th>App</th><th>Data type</th><th>Records</th><th>Fields</th><th>From pack</th></tr></thead><tbody>
      ${domains.map((d) => html`<tr><td><a href="${xHref(d.key)}" class="row" style="gap:8px;flex-wrap:nowrap">${builtinIcon(d.icon, xColor(d.key), "sm")}<b>${d.title}</b></a></td>
        <td class="mono" style="font-size:12.5px">${d.collection}</td>
        <td>${d.count}${d.stale ? html` <span class="faint" style="font-size:12px">+${d.stale} stale</span>` : ""}</td>
        <td class="faint" style="font-size:12.5px">${d.fields.length}</td>
        <td><a href="${packHref(d.extension_id)}">${d.extension_id}</a></td></tr>`)}</tbody></table></div></section>`;
}

function gapsView(data, admin) {
  const byTool = new Map();
  for (const g of data.gaps) byTool.set(g.tool_id, [...(byTool.get(g.tool_id) || []), g]);
  const waiting = new Map(data.extensions.filter((p) => p.status === "proposed" && p.source_tool).map((p) => [p.source_tool, p]));
  const verdict = (g) => (!g.expressible ? badge("needs a change to Atrium's code", "warn") : g.needs_claude ? badge("needs Claude", "") : badge("template available", "info"));
  return html`<p class="muted" style="margin-bottom:14px">What Atrium itself lacks for imported tools - a place for their data, a connector, an SSO recipe.
      After an import the Hub Supervisor asks the Patch Agent to close them once per tool; ask again here.</p>
    ${byTool.size ? html`<div class="stack" style="gap:12px">${[...byTool.entries()].map(([toolId, gaps]) => html`<section class="card">
        <header><div class="row" style="gap:8px"><a href="#/tools/${enc(toolId)}"><b>${gaps[0].tool}</b></a>${gaps[0].category ? badge(CATEGORY[gaps[0].category] || gaps[0].category, "accent") : ""}</div>
          <div class="row" style="gap:6px">${waiting.has(toolId) ? html`<a class="btn sm" href="${packHref(waiting.get(toolId).id)}">${icon("clock")}Proposal waiting</a>` : ""}
            <button type="button" class="btn sm primary" data-act="extend" data-tool="${toolId}" data-name="${gaps[0].tool}" data-min-role="admin"
              ${data.allowed ? "" : "disabled"} title="${data.allowed ? "Ask the Patch Agent to close these gaps" : "Extensions are switched off"}">${icon("puzzle")}Extend Atrium</button></div></header>
        ${gaps.map((g) => html`<div class="check-row"><div class="ico warn">${icon(GAP_ICON[g.kind] || "alert")}</div>
          <div style="flex:1;min-width:0"><div class="row" style="gap:6px"><b>${g.title}</b>${badge(g.kind)}${verdict(g)}</div>
            <p class="muted" style="font-size:12.5px;margin-top:2px;overflow-wrap:anywhere">${g.detail}</p></div></div>`)}</section>`)}</div>`
      : html`<section class="card">${emptyState("checkCircle", "No gaps", "Every imported tool has a place in Atrium for its data, a connector and a known sign-in.")}</section>`}
    ${admin ? "" : html`<p class="faint" style="font-size:12.5px;margin-top:10px">Only administrators ask the Patch Agent to extend Atrium.</p>`}`;
}

function selfPatchesView(data, patches) {
  const a = data.self_patching;
  const ready = a.allowed && a.claude && a.git_checkout;
  const req = (ok, text, hint = "") => html`<div class="check-row"><div class="ico ${ok ? "pass" : "manual"}">${icon(ok ? "check" : "x")}</div>
    <div style="min-width:0"><div>${text}</div>${hint ? html`<div class="faint" style="font-size:12px;overflow-wrap:anywhere">${hint}</div>` : ""}</div></div>`;
  return html`<div class="grid split" style="margin-bottom:16px">
      <section class="card"><header><h2>Changes to Atrium's own code</h2>
          <button type="button" class="btn sm primary" data-act="ask" data-min-role="admin" ${ready ? "" : "disabled"}
            title="${ready ? "Describe a change for the Patch Agent" : "Needs self-patching allowed, Claude and a git checkout"}">${icon("plus")}Ask for a change</button></header>
        <p class="muted" style="font-size:13px">When an extension pack cannot express what a tool needs - a GraphQL or gRPC API, new code - the Patch Agent writes a change with
          Claude on a separate branch in a git worktree, runs the test suite there and asks an administrator. ${a.via_pull_request
          ? "Approved changes become a pull request when the GitHub CLI is signed in and an origin remote exists; otherwise they are merged locally."
          : "Approved changes are merged into the current branch; Atrium must then be restarted."}</p>
        <div class="notice warn" style="margin-top:10px">${icon("alert")}<div class="muted" style="font-size:12.5px">The tests of a proposed change run before anyone approves it, as the same
          operating-system user as Atrium: credentials are stripped from their environment, but files and the network are not sandboxed. Switch off "Allow self-patching" in Settings to rule this out.</div></div></section>
      <section class="card"><header><h2>Can Atrium patch itself?</h2>${ready ? badge("ready", "ok") : badge("not available", "")}</header>
        ${req(a.allowed, "Self-patching allowed", "Guardrail \"Allow self-patching\"")}
        ${req(a.claude, "Claude connected", a.claude ? "" : "Set ANTHROPIC_API_KEY and restart Atrium")}
        ${req(a.git_checkout, "Runs from a git checkout", a.repo || "Installed without git (or HUB_SELF_PATCH=off): nothing to patch")}
        ${req(a.requires_tests, "Tests must pass before approval")}
        ${req(a.requires_approval, "An administrator approves every change")}</section></div>
    <section class="card flush">${patches.length ? html`<div class="table-wrap"><table class="table"><thead><tr>
        <th>Change</th><th>Status</th><th>Tests</th><th>Files</th><th>Applied as</th><th>Requested</th><th></th></tr></thead><tbody>
      ${patches.map((sp) => html`<tr class="clickable" data-act="patch" data-id="${sp.id}">
        <td style="min-width:220px"><b style="overflow-wrap:anywhere">${sp.title}</b><div class="faint mono" style="font-size:11.5px">${sp.branch}</div></td>
        <td>${badge(sp.status)}${sp.error ? html`<div class="flow-result bad" title="${sp.error}">${sp.error}</div>` : ""}</td>
        <td>${sp.tests ? badge(sp.tests_passed ? "passed" : sp.tests.timed_out ? "timed out" : "failed", sp.tests_passed ? "ok" : "bad") : html`<span class="faint">${sp.status === "testing" ? "running..." : "-"}</span>`}</td>
        <td class="faint">${sp.files.length}</td>
        <td>${safeUrl(sp.pr_url) ? html`<a href="${sp.pr_url}" target="_blank" rel="noopener noreferrer" data-act="nav">${icon("external")}pull request</a>`
          : sp.merge_commit ? html`<span class="mono" style="font-size:12px">${sp.merge_commit.slice(0, 10)}</span>` : sp.mode ? html`<span class="faint">${sp.mode === "pull_request" ? "pull request" : "local merge"}</span>` : ""}</td>
        <td class="faint" title="${dateTime(sp.created_at)}">${sp.requested_by} - ${timeAgo(sp.created_at)}</td>
        <td style="text-align:right">${sp.status === "approved" ? html`<button type="button" class="btn sm" data-act="apply" data-id="${sp.id}" data-min-role="admin">${icon("merge")}Apply again</button>` : ""}</td></tr>`)}
      </tbody></table></div>`
      : emptyState("branch", "No self-patches yet", "The Patch Agent proposes one when only a change to Atrium's code can close a gap - or ask for one.")}</section>`;
}

export async function render(el, ctx) {
  const [first, second] = ctx.params;
  let tab = TABS.includes(first) ? first : "packs";
  let data = null;
  let patches = [];
  const admin = can("admin");
  const toolNames = () => Object.fromEntries(ctx.state.tools.map((t) => [t.id, t.name]));

  const draw = async () => {
    const [d, sp] = await Promise.all([get("/extensions"), get("/self-patches")]);
    if (!el.isConnected) return;
    data = d;
    patches = sp.patches;
    const enabled = data.extensions.filter((p) => p.status === "enabled").length;
    const proposed = data.extensions.filter((p) => p.status === "proposed").length + patches.filter((p) => p.status === "proposed").length;
    const records = data.domains.reduce((n, x) => n + x.count, 0);
    const names = toolNames();
    const inner = (label, value, sub, iconName) => html`<div class="stat-icon">${icon(iconName)}</div>
      <div><div class="label">${label}</div><div class="value">${value}</div><div class="sub">${sub}</div></div>`;
    const stat = (label, value, sub, iconName, target) => (target.startsWith("#")
      ? html`<a class="card stat" href="${target}">${inner(label, value, sub, iconName)}</a>`
      : html`<button type="button" class="card stat stat-btn" data-act="tab" data-tab="${target}">${inner(label, value, sub, iconName)}</button>`);
    setHTML(el, html`
      <div class="page-head"><div><h1>Extensions</h1><p class="muted">Packs teach Atrium new data types (each becomes an app), connector mappings, SSO recipes,
          compliance evidence and agent-team templates. Packs are data only - nothing in them is ever executed.</p></div>
        <div class="row" data-min-role="admin"><button type="button" class="btn primary" data-act="upload" ${data.allowed ? "" : "disabled"}>${icon("upload")}Upload pack</button></div></div>
      ${admin ? "" : html`<div class="notice" style="margin-bottom:16px">${icon("lock")}<div class="muted">Only administrators manage extensions and changes to Atrium; you can read everything here.</div></div>`}
      ${data.allowed ? "" : html`<div class="notice warn" style="margin-bottom:16px">${icon("alert")}<div><b>Extensions are switched off.</b>
        <span class="muted">No pack is active and none is proposed while the guardrail "Allow extensions" is off. Packs and records are kept.</span>
        <a href="#/settings" data-min-role="admin">Settings &rarr;</a></div></div>`}
      <div class="grid cols-5" style="margin-bottom:12px">
        ${stat("Enabled packs", enabled, `${data.extensions.length} in all`, "puzzle", "packs")}
        ${stat("Extension apps", data.domains.length, `${records} record${records === 1 ? "" : "s"}`, "grid", "packs")}
        ${stat("Waiting for approval", proposed, "packs and self-patches", "checkCircle", "#/approvals")}
        ${stat("Gaps in Atrium", data.gaps.length, `${new Set(data.gaps.map((g) => g.tool_id)).size} tool(s)`, "alert", "gaps")}
        ${stat("Self-patches", patches.length, `${patches.filter((p) => ["merged", "pull_request"].includes(p.status)).length} applied`, "branch", "self-patches")}
      </div>
      ${guardStrip(data.guardrails)}
      <div class="tabs">${[["packs", `Packs (${data.extensions.length})`], ["gaps", `Gaps (${data.gaps.length})`], ["self-patches", `Self-patches (${patches.length})`]]
        .map(([k, label]) => html`<button type="button" class="${tab === k ? "active" : ""}" data-act="tab" data-tab="${k}">${label}</button>`)}</div>
      ${tab === "packs" ? html`${data.domains.length ? appsCard(data.domains) : ""}
          ${data.extensions.length ? html`<div class="stack" style="gap:12px">${data.extensions.map((p) => packCard(p, admin, names))}</div>`
            : html`<section class="card">${emptyState("puzzle", "No extension packs yet", "After an import the Hub Supervisor looks for what Atrium lacks for the tool, and the Patch Agent proposes a pack. You can also upload one.",
              html`<button type="button" class="btn primary" data-act="upload" data-min-role="admin" ${data.allowed ? "" : "disabled"}>${icon("upload")}Upload pack</button>`)}</section>`}`
        : tab === "gaps" ? gapsView(data, admin) : selfPatchesView(data, patches)}`);
  };
  const refresh = () => draw().catch((err) => toast(err.message, "bad"));
  const find = (id) => data?.extensions.find((p) => p.id === id);
  const activeDomains = (id) => new Set((data?.domains || []).filter((d) => d.extension_id === id).map((d) => d.key));
  const setStatus = async (p, status) => {
    if (status === "disabled" && p.status === "enabled" && !(await confirmDialog(`Disable ${p.name}?`,
      "Its apps leave the sidebar and its data flows stop; its SSO recipes, compliance rules and team templates no longer apply, and its connector mappings are taken out of the tools' connections. Records and versions are kept - enabling it again restores everything.", "Disable"))) return;
    try {
      await patch(`/extensions/${enc(p.id)}`, { status });
      toast(p.status === "proposed" ? (status === "enabled" ? `${p.name} enabled - its proposal is approved` : `${p.name} rejected`)
        : `${p.name} ${status}`, status === "enabled" ? "ok" : "info");
    } catch (err) {
      if (err.status !== 401) toast(err.message, "bad");
    }
    refresh();
  };

  actions(el, {
    tab(d) {
      if (d.tab === tab) return;
      tab = d.tab;
      history.replaceState(null, "", tab === "packs" ? "#/extensions" : `#/extensions/${tab}`);
      draw();
    },
    upload: () => openUpload(refresh),
    toggle(d) {
      const p = find(d.id);
      if (p && admin) setStatus(p, p.status === "enabled" ? "disabled" : "enabled");
    },
    status(d) {
      const p = find(d.id);
      if (p) setStatus(p, d.status);
    },
    details: (d) => openPack(d.id, { activeDomains: activeDomains(d.id), done: refresh }),
    json: (d) => openPack(d.id, { view: "json", done: refresh }),
    versions: (d) => openPack(d.id, { view: "versions", done: refresh }),
    async rollback(d) {
      const p = find(d.id);
      if (!p || !(await confirmDialog(`Roll ${p.name} back to ${d.version}?`, `Version ${d.version} becomes current${p.status === "enabled" ? " at once" : ""}; version ${p.version} is kept and can be made current again.`, "Roll back"))) return;
      try {
        await post(`/extensions/${enc(p.id)}/rollback`, {});
        toast(`${p.name} rolled back to ${d.version}`, "ok");
      } catch (err) {
        if (err.status !== 401) toast(err.message, "bad");
      }
      refresh();
    },
    remove(d) {
      const p = find(d.id);
      if (p) openRemove(p, refresh);
    },
    extend: (d) => openExtend({ id: d.tool, name: d.name }, { claude: data?.self_patching.claude, done: refresh }),
    ask: () => askForChange(ctx.state.tools, data.self_patching, refresh),
    patch: (d) => openSelfPatch(d.id, data?.self_patching, toolNames(), refresh),
    async apply(d, btn) {
      btn.disabled = true;
      try {
        const r = await post(`/self-patches/${enc(d.id)}/apply`);
        toast(r.detail || (r.ok ? "Applied" : "Not applied"), r.ok ? "ok" : "bad");
      } catch (err) {
        if (err.status !== 401) toast(err.message, "bad");
      }
      refresh();
    },
  });
  await draw();
  // #/extensions/packs/<id> and #/extensions/self-patches/<id> open that pack or self-patch (links from apps and Approvals)
  if (second && first === "packs") openPack(second, { activeDomains: activeDomains(second), done: refresh });
  if (second && first === "self-patches") openSelfPatch(second, data.self_patching, toolNames(), refresh);
  if (second) history.replaceState(null, "", tab === "packs" ? "#/extensions" : `#/extensions/${tab}`);
  ctx.live(LIVE, refresh, 600);
}
